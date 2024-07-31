package rtsp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	rtspauth "github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/google/uuid"
	"github.com/pion/rtp"
	"github.com/pion/rtcp"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/stream"
)

type session struct {
	isTLS           bool
	protocols       map[conf.Protocol]struct{}
	rsession        *gortsplib.ServerSession
	rconn           *gortsplib.ServerConn
	rserver         *gortsplib.Server
	externalCmdPool *externalcmd.Pool
	pathManager     serverPathManager
	parent          *Server

	uuid            uuid.UUID
	created         time.Time
	path            defs.Path
	stream          *stream.Stream
	onUnreadHook    func()
	mutex           sync.Mutex
	state           gortsplib.ServerSessionState
	transport       *gortsplib.Transport
	pathName        string
	query           string
	decodeErrLogger logger.Writer
	writeErrLogger  logger.Writer
}

type RTCPFeedbackMap struct {
    mu sync.Mutex
    // These are pairs of publisher {SSRCs: UDP socket} for sending PLIs upstream
    publisherRTCPFeedbackSockets map[uint32]*net.UDPAddr
}

var udpConn *net.UDPConn = nil
var remoteRTCPAddr *net.UDPAddr = nil
var feedbackMap *RTCPFeedbackMap = nil

func (f *RTCPFeedbackMap) addBinding(ssrc uint32, address *net.UDPAddr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publisherRTCPFeedbackSockets[ssrc] = address
	log.Printf("Added %v as %s to %v", address, ssrc, f.publisherRTCPFeedbackSockets)
}

func (f *RTCPFeedbackMap) deleteBinding(ssrc uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.publisherRTCPFeedbackSockets, ssrc)
	log.Printf("Deleted %v from %v", ssrc, f.publisherRTCPFeedbackSockets)
}

func (f *RTCPFeedbackMap) forwardPLI(ssrc uint32, pkt rtcp.Packet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if remoteRTCPAddr, exists := f.publisherRTCPFeedbackSockets[ssrc]; exists {
		rtcpBytes, _ := pkt.Marshal()
		log.Printf("Sending %v to %v for SSRC %v", rtcpBytes, remoteRTCPAddr, ssrc)
		udpConn.WriteToUDP(rtcpBytes, remoteRTCPAddr)
	} else {
		log.Printf("Dropping PLI with MediaSSRC %v not found in %v", ssrc, f.publisherRTCPFeedbackSockets)
	}
}

func init() {

	feedbackMap = new(RTCPFeedbackMap)
	feedbackMap.publisherRTCPFeedbackSockets = make(map[uint32]*net.UDPAddr)

	const DEFAULT_LATCH_PORT = uint64(54321)

	publisherLatchPort := DEFAULT_LATCH_PORT
	var err error = nil
	if publisherLatchPortStr, ok := os.LookupEnv("PUBLISHER_LATCH_PORT"); ok {
		publisherLatchPort, err = strconv.ParseUint(publisherLatchPortStr, 10, 32)
		if err != nil {
			log.Printf("Error parsing %v", publisherLatchPortStr)
			return
		}
	}

	addr := net.UDPAddr{
		Port: int(publisherLatchPort),
		IP: net.ParseIP("0.0.0.0"),
	}

	if udpConn == nil {
		var err error
		udpConn, err = net.ListenUDP("udp", &addr)
		if err != nil {
			log.Printf("Error on listening %v", err)
		} else {
			log.Printf("Listening to %v to discover where to send RTCP", addr)
		}
	}

	// This goroutine will get a dummy packet whose source is where we will send RTCP feedback
	go func() {
		buffer := make([]byte, 64)
		if udpConn == nil {
			return
		}
		bytesReceived, remoteRTCPAddr, socketErr := 0, new(net.UDPAddr), error(nil)
		for socketErr == nil {
			bytesReceived, remoteRTCPAddr, socketErr = udpConn.ReadFromUDP(buffer)
			if socketErr != nil {
				return
			}
			tokens := strings.Split(string(buffer[:bytesReceived]), " ")
			if len(tokens) < 2 {
				log.Printf("Error parsing %v", buffer[:bytesReceived])
				return
			}
			method := tokens[0]
			publisherId, err := strconv.ParseUint(tokens[1], 10, 32)
			if err != nil {
				log.Printf("Error parsing %v", buffer[:bytesReceived])
				return
			}
			log.Printf("Read a message from %v (%d bytes): %v %v", remoteRTCPAddr, bytesReceived, method, publisherId)
			switch {
			case method == "POST":
				feedbackMap.addBinding(uint32(publisherId), remoteRTCPAddr)
			case method == "DELETE":
				feedbackMap.deleteBinding(uint32(publisherId))
			default:
				log.Printf("Unexpected method %v", method)
			}
		}
	}()
}

func (s *session) initialize() {
	s.uuid = uuid.New()
	s.created = time.Now()

	s.decodeErrLogger = logger.NewLimitedLogger(s)
	s.writeErrLogger = logger.NewLimitedLogger(s)

	s.Log(logger.Info, "created by %v", s.rconn.NetConn().RemoteAddr())
}

// Close closes a Session.
func (s *session) Close() {
	s.rsession.Close()
}

func (s *session) remoteAddr() net.Addr {
	return s.rconn.NetConn().RemoteAddr()
}

// Log implements logger.Writer.
func (s *session) Log(level logger.Level, format string, args ...interface{}) {
	id := hex.EncodeToString(s.uuid[:4])
	s.parent.Log(level, "[session %s] "+format, append([]interface{}{id}, args...)...)
}

// onClose is called by rtspServer.
func (s *session) onClose(err error) {
	if s.rsession.State() == gortsplib.ServerSessionStatePlay {
		s.onUnreadHook()
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStatePrePlay, gortsplib.ServerSessionStatePlay:
		s.path.RemoveReader(defs.PathRemoveReaderReq{Author: s})

	case gortsplib.ServerSessionStatePreRecord, gortsplib.ServerSessionStateRecord:
		s.path.RemovePublisher(defs.PathRemovePublisherReq{Author: s})
	}

	s.path = nil
	s.stream = nil

	s.Log(logger.Info, "destroyed: %v", err)
}

// onAnnounce is called by rtspServer.
func (s *session) onAnnounce(c *conn, ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	if c.authNonce == "" {
		var err error
		c.authNonce, err = rtspauth.GenerateNonce()
		if err != nil {
			return &base.Response{
				StatusCode: base.StatusInternalServerError,
			}, err
		}
	}

	path, err := s.pathManager.AddPublisher(defs.PathAddPublisherReq{
		Author: s,
		AccessRequest: defs.PathAccessRequest{
			Name:        ctx.Path,
			Query:       ctx.Query,
			Publish:     true,
			IP:          c.ip(),
			Proto:       auth.ProtocolRTSP,
			ID:          &c.uuid,
			RTSPRequest: ctx.Request,
			RTSPNonce:   c.authNonce,
		},
	})
	if err != nil {
		var terr auth.Error
		if errors.As(err, &terr) {
			return c.handleAuthError(terr)
		}

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.path = path

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStatePreRecord
	s.pathName = ctx.Path
	s.query = ctx.Query
	s.mutex.Unlock()

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onSetup is called by rtspServer.
func (s *session) onSetup(c *conn, ctx *gortsplib.ServerHandlerOnSetupCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	// in case the client is setupping a stream with UDP or UDP-multicast, and these
	// transport protocols are disabled, gortsplib already blocks the request.
	// we have only to handle the case in which the transport protocol is TCP
	// and it is disabled.
	if ctx.Transport == gortsplib.TransportTCP {
		if _, ok := s.protocols[conf.Protocol(gortsplib.TransportTCP)]; !ok {
			return &base.Response{
				StatusCode: base.StatusUnsupportedTransport,
			}, nil, nil
		}
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStateInitial, gortsplib.ServerSessionStatePrePlay: // play
		if c.authNonce == "" {
			var err error
			c.authNonce, err = rtspauth.GenerateNonce()
			if err != nil {
				return &base.Response{
					StatusCode: base.StatusInternalServerError,
				}, nil, err
			}
		}

		path, stream, err := s.pathManager.AddReader(defs.PathAddReaderReq{
			Author: s,
			AccessRequest: defs.PathAccessRequest{
				Name:        ctx.Path,
				Query:       ctx.Query,
				IP:          c.ip(),
				Proto:       auth.ProtocolRTSP,
				ID:          &c.uuid,
				RTSPRequest: ctx.Request,
				RTSPNonce:   c.authNonce,
			},
		})
		if err != nil {
			var terr auth.Error
			if errors.As(err, &terr) {
				res, err2 := c.handleAuthError(terr)
				return res, nil, err2
			}

			var terr2 defs.PathNoOnePublishingError
			if errors.As(err, &terr2) {
				return &base.Response{
					StatusCode: base.StatusNotFound,
				}, nil, err
			}

			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, nil, err
		}

		s.path = path
		s.stream = stream

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.pathName = ctx.Path
		s.query = ctx.Query
		s.mutex.Unlock()

		var rstream *gortsplib.ServerStream
		if !s.isTLS {
			rstream = stream.RTSPStream(s.rserver)
		} else {
			rstream = stream.RTSPSStream(s.rserver)
		}

		return &base.Response{
			StatusCode: base.StatusOK,
		}, rstream, nil

	default: // record
		return &base.Response{
			StatusCode: base.StatusOK,
		}, nil, nil
	}
}

// onPlay is called by rtspServer.
func (s *session) onPlay(_ *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	h := make(base.Header)

	if s.rsession.State() == gortsplib.ServerSessionStatePrePlay {
		s.Log(logger.Info, "is reading from path '%s', with %s, %s",
			s.path.Name(),
			s.rsession.SetuppedTransport(),
			defs.MediasInfo(s.rsession.SetuppedMedias()))

		s.onUnreadHook = hooks.OnRead(hooks.OnReadParams{
			Logger:          s,
			ExternalCmdPool: s.externalCmdPool,
			Conf:            s.path.SafeConf(),
			ExternalCmdEnv:  s.path.ExternalCmdEnv(),
			Reader:          s.APIReaderDescribe(),
			Query:           s.rsession.SetuppedQuery(),
		})

		for _, medi := range s.rsession.SetuppedMedias() {
			for _, _ = range medi.Formats {
				s.rsession.OnPacketRTCPAny(func(medi *description.Media, pkt rtcp.Packet) {
					switch p := pkt.(type) {
					case *rtcp.PictureLossIndication:
						s.Log(logger.Warn, "Got PLI packet %v, %d bytes\n", p, pkt.MarshalSize())
						feedbackMap.forwardPLI(p.MediaSSRC, pkt)
					default:
						s.Log(logger.Debug, "Got RTCP packet %v, %d bytes\n", p, pkt.MarshalSize())
					}
				})
			}
		}

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePlay
		s.transport = s.rsession.SetuppedTransport()
		s.mutex.Unlock()
	}

	return &base.Response{
		StatusCode: base.StatusOK,
		Header:     h,
	}, nil
}

// onRecord is called by rtspServer.
func (s *session) onRecord(_ *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	stream, err := s.path.StartPublisher(defs.PathStartPublisherReq{
		Author:             s,
		Desc:               s.rsession.AnnouncedDescription(),
		GenerateRTPPackets: false,
	})
	if err != nil {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.stream = stream

	for _, medi := range s.rsession.AnnouncedDescription().Medias {
		for _, forma := range medi.Formats {
			cmedi := medi
			cforma := forma

			s.rsession.OnPacketRTP(cmedi, cforma, func(pkt *rtp.Packet) {
				pts, ok := s.rsession.PacketPTS(cmedi, pkt)
				if !ok {
					return
				}

				stream.WriteRTPPacket(cmedi, cforma, pkt, time.Now(), pts)
			})
		}
	}

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStateRecord
	s.transport = s.rsession.SetuppedTransport()
	s.mutex.Unlock()

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onPause is called by rtspServer.
func (s *session) onPause(_ *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	switch s.rsession.State() {
	case gortsplib.ServerSessionStatePlay:
		s.onUnreadHook()

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.mutex.Unlock()

	case gortsplib.ServerSessionStateRecord:
		s.path.StopPublisher(defs.PathStopPublisherReq{Author: s})

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePreRecord
		s.mutex.Unlock()
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// APIReaderDescribe implements reader.
func (s *session) APIReaderDescribe() defs.APIPathSourceOrReader {
	return defs.APIPathSourceOrReader{
		Type: func() string {
			if s.isTLS {
				return "rtspsSession"
			}
			return "rtspSession"
		}(),
		ID: s.uuid.String(),
	}
}

// APISourceDescribe implements source.
func (s *session) APISourceDescribe() defs.APIPathSourceOrReader {
	return s.APIReaderDescribe()
}

// onPacketLost is called by rtspServer.
func (s *session) onPacketLost(ctx *gortsplib.ServerHandlerOnPacketLostCtx) {
	s.decodeErrLogger.Log(logger.Warn, ctx.Error.Error())
}

// onDecodeError is called by rtspServer.
func (s *session) onDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.decodeErrLogger.Log(logger.Warn, ctx.Error.Error())
}

// onStreamWriteError is called by rtspServer.
func (s *session) onStreamWriteError(ctx *gortsplib.ServerHandlerOnStreamWriteErrorCtx) {
	s.writeErrLogger.Log(logger.Warn, ctx.Error.Error())
}

func (s *session) apiItem() *defs.APIRTSPSession {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return &defs.APIRTSPSession{
		ID:         s.uuid,
		Created:    s.created,
		RemoteAddr: s.remoteAddr().String(),
		State: func() defs.APIRTSPSessionState {
			switch s.state {
			case gortsplib.ServerSessionStatePrePlay,
				gortsplib.ServerSessionStatePlay:
				return defs.APIRTSPSessionStateRead

			case gortsplib.ServerSessionStatePreRecord,
				gortsplib.ServerSessionStateRecord:
				return defs.APIRTSPSessionStatePublish
			}
			return defs.APIRTSPSessionStateIdle
		}(),
		Path:  s.pathName,
		Query: s.query,
		Transport: func() *string {
			if s.transport == nil {
				return nil
			}
			v := s.transport.String()
			return &v
		}(),
		BytesReceived: s.rsession.BytesReceived(),
		BytesSent:     s.rsession.BytesSent(),
	}
}
