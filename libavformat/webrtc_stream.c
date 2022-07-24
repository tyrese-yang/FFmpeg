#include <pthread.h>
#include <unistd.h>

#include "libavutil/avstring.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavformat/avformat.h"
#include "libavformat/url.h"
#include "libavformat/http.h"
#include "libavformat/internal.h"
#include "libavutil/avutil.h"
#include "libavutil/intreadwrite.h"
#include "libavcodec/get_bits.h"
#include "libavcodec/h264.h"

#include "webrtc_stream.h"

#define STUN_BINDING_INTERVAL 2000 // ms
#define STUN_BINDING_PASSWORD "ffmpeg"
#define LOCAL_ICE_UFRAG "ffmpeg"

#define DTS_EXTMAP 10
#define CTS_EXTMAP 18

const char *OFFER_SDP = "v=0\r\n"
    "o=- 0 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "i=ffmpeg\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0 1\r\n"
    "a=extmap-allow-mixed\r\n"
    "a=msid-semantic: WMS\r\n"
    "m=audio 9 RTP/AVPF 122 123\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:"LOCAL_ICE_UFRAG"\r\n"
    "a=ice-pwd:y3yqjhruMPu9GFrOGF/WBN3q\r\n"
    "a=ice-options:trickle\r\n"
    "a=mid:0\r\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
    "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
    "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
    "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
    "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-01\r\n"
    "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-02\r\n"
    "a=extmap:9 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-03\r\n"
    "a=extmap:10 http://www.webrtc.org/experiments/rtp-hdrext/decoding-timestamp\r\n"
    "a=recvonly\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:122 MP4A-ADTS/48000/2\r\n"
    "a=rtcp-fb:122 transport-cc\r\n"
    "a=rtpmap:123 MP4A-ADTS/44100/2\r\n"
    "a=rtcp-fb:123 transport-cc\r\n"
    "m=video 9 RTP/AVPF 96 97 98 99 100 101 102\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:"LOCAL_ICE_UFRAG"\r\n"
    "a=ice-pwd:y3yqjhruMPu9GFrOGF/WBN3q\r\n"
    "a=ice-options:trickle\r\n"
    "a=mid:1\r\n"
    "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n"
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    "a=extmap:13 urn:3gpp:video-orientation\r\n"
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
    "a=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
    "a=extmap:11 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n"
    "a=extmap:15 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n"
    "a=extmap:16 http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07\r\n"
    "a=extmap:17 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n"
    "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
    "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
    "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
    "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-01\r\n"
    "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-02\r\n"
    "a=extmap:9 http://www.webrtc.org/experiments/rtp-hdrext/meta-data-03\r\n"
    "a=extmap:10 http://www.webrtc.org/experiments/rtp-hdrext/decoding-timestamp\r\n"
    "a=extmap:18 http://www.webrtc.org/experiments/rtp-hdrext/video-composition-time\r\n"
    "a=extmap:19 http://www.webrtc.org/experiments/rtp-hdrext/video-frame-type\r\n"
    "a=recvonly\r\n"
    "a=rtcp-mux\r\n"
    "a=rtcp-rsize\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    // "a=rtcp-fb:96 goog-remb\r\n"
    // "a=rtcp-fb:96 transport-cc\r\n"
    // "a=rtcp-fb:96 ccm fir\r\n"
    // "a=rtcp-fb:96 nack\r\n"
    // "a=rtcp-fb:96 nack pli\r\n"
    // "a=rtcp-fb:96 rrtr\r\n"
    "a=fmtp:96 bframe-enabled=1;level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\r\n"
    "a=rtpmap:97 rtx/90000\r\n"
    "a=fmtp:97 apt=96\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    // "a=rtcp-fb:98 goog-remb\r\n"
    // "a=rtcp-fb:98 transport-cc\r\n"
    // "a=rtcp-fb:98 ccm fir\r\n"
    // "a=rtcp-fb:98 nack\r\n"
    // "a=rtcp-fb:98 nack pli\r\n"
    // "a=rtcp-fb:98 rrtr\r\n"
    "a=fmtp:98 bframe-enabled=1;level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
    "a=rtpmap:99 rtx/90000\r\n"
    "a=fmtp:99 apt=98\r\n"
    "a=rtpmap:100 red/90000\r\n"
    "a=rtpmap:101 rtx/90000\r\n"
    "a=fmtp:101 apt=100\r\n"
    "a=rtpmap:102 ulpfec/90000\r\n";

static int webrtc_stream_close(AVFormatContext *h)
{
    av_log(h, AV_LOG_INFO, "webrtc_stream_close exit\n");
    return 0;
}

static int webrtc_stream_probe(const AVProbeData *p)
{
    if (av_strstart(p->filename, "webrtc:", NULL))
        return AVPROBE_SCORE_MAX;
    return 0;
}

static RTPPacket *rtp_packet_alloc()
{
    return av_mallocz(sizeof(RTPPacket));
}

static void rtp_packet_free(RTPPacket *pkt)
{
    if (pkt) {
        free(pkt->playload);
        free(pkt);
    }
}

static RTPMedia *rtp_media_create(SDP *sdp)
{
    av_log(NULL, AV_LOG_DEBUG, "m=%p n=%d\n", sdp->medias, sdp->nb_medias + 1);
    RTPMedia **medias = av_realloc_array(sdp->medias, sdp->nb_medias + 1, sizeof(*medias));
    sdp->medias = medias;
    RTPMedia *m = av_mallocz(sizeof(RTPMedia));
    sdp->medias[sdp->nb_medias++] = m;
    return m;
}

static RTPMedia *rtp_media_get(const SDP *sdp, uint16_t pt)
{
    for (int i = 0; i < sdp->nb_medias; i++) {
        if (sdp->medias[i]->pt == pt) {
            return sdp->medias[i];
        }
    }
    return NULL;
}

static RTPStream *rtp_stream_create(WebrtcStreamContext *ctx)
{
    RTPStream **streams = av_realloc_array(ctx->rtp_streams, ctx->nb_rtp_streams + 1, sizeof(*streams));
    ctx->rtp_streams = streams;
    RTPStream *rs = av_mallocz(sizeof(RTPStream));
    ctx->rtp_streams[ctx->nb_rtp_streams++] = rs;
    return rs;
}

static RTPStream *rtp_stream_get(WebrtcStreamContext *ctx, uint8_t pt)
{
    for (int i = 0; i < ctx->nb_rtp_streams; i++) {
        if (ctx->rtp_streams[i]->pt == pt) {
            return ctx->rtp_streams[i];
        }
    }
    return NULL;
}

static void queue_init(AVFormatContext *avctx, AVPacketQueue *q)
{
    memset(q, 0, sizeof(AVPacketQueue));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->avctx = avctx;
    // TODO: set by argument
    q->max_q_size = 5 * 1024 * 1024;
}

static unsigned long long queue_size(AVPacketQueue *q)
{
    unsigned long long size;
    pthread_mutex_lock(&q->mutex);
    size = q->size;
    pthread_mutex_unlock(&q->mutex);
    return size;
}

static int queue_put(AVPacketQueue *q, AVPacket *pkt)
{
    PacketList *pkt1;

    if (queue_size(q) > (uint64_t)q->max_q_size) {
        av_packet_unref(pkt);
        av_log(q->avctx, AV_LOG_WARNING,  "Decklink input buffer overrun!\n");
        return -1;
    }

    /* Ensure the packet is reference counted */
    if (av_packet_make_refcounted(pkt) < 0) {
        av_packet_unref(pkt);
        return -1;
    }

    pkt1 = (PacketList *)av_mallocz(sizeof(PacketList));
    if (!pkt1) {
        av_packet_unref(pkt);
        return -1;
    }
    av_packet_move_ref(&pkt1->pkt, pkt);
    pkt1->next = NULL;

    pthread_mutex_lock(&q->mutex);

    if (!q->last_pkt) {
        q->first_pkt = pkt1;
    } else {
        q->last_pkt->next = pkt1;
    }

    q->last_pkt = pkt1;
    q->nb_packets++;
    q->size += pkt1->pkt.size + sizeof(*pkt1);

    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
    return 0;
}

static int queue_get(AVPacketQueue *q, AVPacket *pkt, int block)
{
    PacketList *pkt1;
    int ret;

    pthread_mutex_lock(&q->mutex);

    for (;;) {
        pkt1 = q->first_pkt;
        if (pkt1) {
            q->first_pkt = pkt1->next;
            if (!q->first_pkt) {
                q->last_pkt = NULL;
            }
            q->nb_packets--;
            q->size -= pkt1->pkt.size + sizeof(*pkt1);
            *pkt     = pkt1->pkt;
            av_free(pkt1);
            ret = 1;
            break;
        } else if (!block) {
            ret = 0;
            break;
        } else {
            pthread_cond_wait(&q->cond, &q->mutex);
        }
    }
    pthread_mutex_unlock(&q->mutex);
    return ret;
}

static int send_offer(URLContext **puc, AVFormatContext *s, const char* api,
                      const char *offer)
{
    uint8_t buf[16*1024] = {0};
    const char *fmt = "{\"clientinfo\":\"ffmpeg\","
                        "\"sessionid\":\"1\","
                        "\"streamurl\":\"%s\","
                        "\"localsdp\":{"
                            "\"type\":\"offer\","
                            "\"sdp\":\"%s\""
                        "}}";
    sprintf(buf, fmt, s->url, offer);

    ffurl_alloc(puc, api, AVIO_FLAG_READ_WRITE, NULL);
    av_opt_set_bin((*puc)->priv_data, "post_data", buf, strlen(buf), 0);
    return ffurl_connect(*puc, NULL);
}

static char *read_line_arg(char *buf, int buf_size, const char *data, const char *split)
{
    char *next = av_stristr(data, split);
    if (buf) {
        if (next)
            memcpy(buf, data, next - data > buf_size ? buf_size : next - data);
        else
            strncpy(buf, data, buf_size);
    }
    return next ? next + 1 : NULL;
}

static int parse_attr(SDP *sdp, const char *data, int len)
{
    const char *v = NULL;
    char line[1024] = {0};
    char buf[128] = {0};

    memcpy(line, data, len);

    if (av_strstart(line, "ice-ufrag:", &v)) {
        memcpy(sdp->ice_ufrag, v, len - (v - line));
    } else if (av_strstart(line, "candidate:", &v)) {
        // a=candidate:foundation 1 udp 100 27.159.95.33 8000 typ srflx raddr 27.159.95.33 rport 8000 generation 0
        // TODO: support multi candidate
        if (strlen(sdp->candidate.ip) == 0)
            sscanf(v, "%*s %*d %*s %*d %s %hd %*s", sdp->candidate.ip, &sdp->candidate.port);
    } else if (av_strstart(line, "fmtp:", &v)) {
        // a=fmtp:123 PS-enabled=0;SBR-enabled=0;config=40002420adca1fe0;cpresent=0;object=2;profile-level-id=1;stereo=1
        int l = av_stristr(v, " ") - v;
        memcpy(buf, v, l);
        int pt = atoi(buf);
        RTPMedia *m = rtp_media_get(sdp, pt);
        if (m) {
            switch (m->type) {
            case AVMEDIA_TYPE_AUDIO: {
                v += l + 1;
                const char *next = v;
                while(next) {
                    memset(buf, 0, sizeof(buf));
                    next = read_line_arg(buf, sizeof(buf), next, ";");
                    const char *vv;
                    if (av_stristart(buf, "PS-enabled=", &vv)) {
                        m->ps = atoi(vv);
                    } else if (av_stristart(buf, "SBR-enabled=", &vv)) {
                        m->sbr = atoi(vv);
                    } else if (av_stristart(buf, "config=", &vv)) {
                        memcpy(m->config, vv, strlen(vv));
                    } else if (av_stristart(buf, "object=", &vv)) {
                        m->object = atoi(vv);
                    } else if (av_stristart(buf, "profile-level-id=", &vv)) {
                        m->audio_pl_id = atoi(vv);
                    }
                }
                break;
            }
            case AVMEDIA_TYPE_VIDEO:{
                v += l + 1;
                const char *next = v;
                while(next) {
                    memset(buf, 0, sizeof(buf));
                    next = read_line_arg(buf, sizeof(buf), next, ";");
                    const char *vv;
                    if (av_stristart(buf, "bframe-enabled=", &vv)) {
                        m->bframe_enabled = atoi(vv);
                    } else if (av_stristart(buf, "level-asymmetry-allowed=", &vv)) {
                        m->level_asymmetry_allowed = atoi(vv);
                    } else if (av_stristart(buf, "packetization-mode=", &vv)) {
                        m->packetization_mode = atoi(vv);
                    } else if (av_stristart(buf, "profile-level-id=", &vv)) {
                        memcpy(m->video_pl_id, vv, strlen(vv));
                    }
                }
                av_log(NULL, AV_LOG_DEBUG, "bf=%d laa=%d pli=%s\n", m->bframe_enabled, m->level_asymmetry_allowed, m->video_pl_id);
                break;
            }
            default:
                break;
            }
        }
    } else if (av_strstart(line, "rtpmap:", &v)) {
        // a=rtpmap:123 MP4A-ADTS/44100/2
        int l = 0;
        l = av_stristr(v, " ") - v;
        memcpy(buf, v, l);
        int pt = atoi(buf);
        RTPMedia *m = rtp_media_get(sdp, pt);
        if (m) {
            switch (m->type) {
            case AVMEDIA_TYPE_AUDIO:
                v += l+1;
                // skip type
                // TODO: check type
                v = av_stristr(v, "/") + 1;

                l = av_stristr(v, "/") - v;
                memset(buf, 0, sizeof(buf));
                memcpy(buf, v, l);
                int sample_rate = atoi(buf);

                v += l+1;
                l = len - (v-line);
                memset(buf, 0, sizeof(buf));
                memcpy(buf, v, l);
                int channel = atoi(buf);

                m->channel = channel;
                m->sample_rate = sample_rate;
                av_log(NULL, AV_LOG_DEBUG, "channel=%d sample_rate=%d\n", channel, sample_rate);
                break;
            case AVMEDIA_TYPE_VIDEO:
                break;
            default:
                break;
            }
        }
    }

    return 0;
}

static int parse_mline(SDP *sdp, const char *data, int len)
{
    char line[1024] = {0};
    memcpy(line, data, len);

    if (av_strstart(line, "audio", NULL)) {
        // m=audio 1 RTP/AVPF 123
        char *next = read_line_arg(NULL, 0, line, " ");
        if (next)
            next = read_line_arg(NULL, 0, next, " ");
        if (next)
            next = read_line_arg(NULL, 0, next, " ");
        while (next) {
            char buf[8] = {0};
            next = read_line_arg(buf, sizeof(buf), next, " ");
            RTPMedia *m = rtp_media_create(sdp);
            m->pt = atoi(buf);
            m->type = AVMEDIA_TYPE_AUDIO;
        }
    } else if (av_strstart(line, "video", NULL)) {
        char *next = read_line_arg(NULL, 0, line, " ");
        if (next)
            next = read_line_arg(NULL, 0, next, " ");
        if (next)
            next = read_line_arg(NULL, 0, next, " ");
        while (next) {
            char buf[8] = {0};
            next = read_line_arg(buf, sizeof(buf), next, " ");
            RTPMedia *m = rtp_media_create(sdp);
            m->pt = atoi(buf);
            m->type = AVMEDIA_TYPE_VIDEO;
        }
    }

    return 0;
}

static int parse_line(SDP *sdp, const char *line, int len)
{
    av_log(NULL, AV_LOG_DEBUG, "parse line %.*s\n", len, line);

    switch(line[0]) {
    case 'a':
        return parse_attr(sdp, line+2, len-2);
    case 'm':
        return parse_mline(sdp, line+2, len-2);
    default:
        return 0;
    }
    return 0;
}

static int parse_sdp(SDP *sdp, const char *data, int size)
{
    const char *pos = data;
    char *line_end = NULL;
    int len = 0;

    for (;;) {
        if ((line_end = av_stristr(pos, "\\r"))
            || (line_end = av_stristr(pos, "\\n"))
            || (line_end = av_stristr(pos, "\r"))
            || (line_end = av_stristr(pos, "\n"))) {

            len = line_end ? line_end - pos : size;
        } else {
            break;
        }

        if (parse_line(sdp, pos, len) < 0) {
            return AVERROR_INVALIDDATA;
        }

        pos += len;
        for (;;) {
            if (*pos == '\r' || *pos == '\n') {
                pos++;
            } else if (*pos == '\\'
                       && (*(pos+1) == 'r' || *(pos+1) == 'n')) {
                pos += 2;
            } else {
                break;
            }
        }

        if (pos - data >= size) {
            break;
        }
    }
    return 0;
}

static int parse_answer(Answer *answer, const char *data)
{
    char *end;
    char *pos = av_stristr(data, "\"sdp\":");
    if (!pos) {
        return AVERROR_INVALIDDATA;
    }

    pos += strlen("\"sdp\":");
    pos = av_stristr(pos, "\"") + 1;
    end = av_stristr(pos, "\"");
    return parse_sdp(&answer->sdp, pos, end - pos);
}

static int is_rtp(const uint8_t *data, int size)
{
    if ((size > 12) && (data[0] & 0x80)) {
        if (data[1] >= 192 && data[1] <= 223) {
            // is rtcp
            return 0;
        }
        return 1;
    }
    return 0;
}

static int is_rtcp(const uint8_t *data, int size)
{
    return (size > 12) && (data[0] & 0x80) && (data[1] >= 192 && data[1] <= 223);
}

#define NAL_MASK 0x1f
static const uint8_t start_sequence[] = { 0, 0, 0, 1 };

static int h264_handle_packet_fu_a(AVPacket *pkt, const uint8_t *buf, int len)
{
    if (len < 3) {
        return AVERROR_INVALIDDATA;
    }

    uint8_t fu_indicator = buf[0];
    uint8_t fu_header    = buf[1];
    uint8_t start_bit    = fu_header >> 7;
    // uint8_t end_bit      = (fu_header >> 6) & 0x01;
    uint8_t nal_type     = fu_header & 0x1f;
    uint8_t nal_header   = fu_indicator & 0xe0 | nal_type;
    uint8_t nal_header_len = 1;

    /* Skip the fu_indicator and fu_header */
    buf += 2;
    len -= 2;

    int ret;
    int pos = 0;
    if (start_bit) {
        int tot_len = len;
        tot_len += sizeof(start_sequence) + nal_header_len;
        if ((ret = av_new_packet(pkt, tot_len)) < 0)
            return ret;
        memcpy(pkt->data + pos, start_sequence, sizeof(start_sequence));
        pos += sizeof(start_sequence);
        memcpy(pkt->data + pos, &nal_header, nal_header_len);
        pos += nal_header_len;
        memcpy(pkt->data + pos, buf, len);
        if (nal_type == H264_NAL_IDR_SLICE || nal_type == H264_NAL_SPS || nal_type == H264_NAL_PPS)
            pkt->flags |= AV_PKT_FLAG_KEY;
    } else {
        pos = pkt->size;
        if ((ret = av_grow_packet(pkt, len)) < 0)
            return ret;
        memcpy(pkt->data + pos, buf, len);
    }

    return 0;
}

static int is_fragment(RTPPacket *pkt)
{
    uint8_t *buf = pkt->playload;
    uint8_t nal  = buf[0];
    uint8_t type = nal & 0x1f;
    return type == 28;
}

static int is_start_frag(RTPPacket *pkt)
{
    uint8_t *buf         = pkt->playload;
    uint8_t fu_header    = buf[1];
    uint8_t start_bit    = fu_header >> 7;
    return start_bit;
}

static int is_end_frag(RTPPacket *pkt)
{
    uint8_t *buf         = pkt->playload;
    uint8_t fu_header    = buf[1];
    uint8_t end_bit      = (fu_header >> 6) & 0x01;
    return end_bit;
}

static int write_rtp_packet_to_buffer(RTPStream *rs, RTPPacket *pkt)
{
    if (!rs->buf) {
        rs->buf_len = 1024;
        rs->buf = av_mallocz(rs->buf_len * sizeof(RTPPacket *));
    }

    int index = pkt->seq % rs->buf_len;
    if (rs->buf[index]) {
        if (rs->buf[index]->seq == pkt->seq) {
            /* Duplicated */
            rtp_packet_free(pkt);
            return 0;
        }
        rtp_packet_free(rs->buf[index]);
    }

    rs->buf[index] = pkt;

    if (!rs->first) {
        rs->seq = pkt->seq;
        rs->first = 1;
    }

    rs->packet_num++;
    if (rs->packet_num > rs->buf_len) {
        /* Buffer over flow, move seq to new frame */
        uint32_t i = rs->seq; 
        while (i - rs->seq < rs->buf_len) {
            RTPPacket *cur = rs->buf[i % rs->buf_len];
            if (cur) {
                if (!is_fragment(cur) || is_start_frag(cur)) {
                    rs->packet_num -= (i - rs->seq);
                    rs->seq = cur->seq;
                    break;
                }
            }
            i++;
        }
    }

    return 0;
}

static int seq_compare(uint16_t a, uint16_t b)
{
#define SEQ_DIST (UINT16_MAX / 2)

    if ((a > b && a - b > SEQ_DIST) ||
        (a < b && b - a < SEQ_DIST))
    {
        return -1;
    } else if ((a > b && a - b < SEQ_DIST) ||
               (a < b && b - a > SEQ_DIST))
    {
        return 1;
    } else {
        return 0;
    }
}

static int read_avpackets_from_buffer(RTPStream *rs, PacketList **pkt_list)
{
    int index = rs->seq % rs->buf_len;
    RTPPacket *cur = rs->buf[index], *start = NULL;
    int last_seq = -1;

    while (cur) {
        if (last_seq != -1 && 
            cur->seq != (last_seq + 1) % (INT16_MAX + 1)) {
            /* RTP packet discontinue */
            break;
        }
        last_seq = cur->seq;

        if (is_fragment(cur)) {
            if (start && cur->ts != start->ts) {
                /* Frame discontinue */
                break;
            }

            if (is_start_frag(cur)) {
                start = cur;
            } else if (is_end_frag(cur)) {
                if (start) {
                    uint16_t i = start->seq;
                    uint16_t start_seq = start->seq;
                    uint16_t end_seq = cur->seq;
                    for (; seq_compare(i, end_seq) <= 0; i++) {
                        RTPPacket *rtp = rs->buf[i % rs->buf_len];
                        if (i == start_seq) {
                            if (*pkt_list == NULL) {
                                *pkt_list = av_mallocz(sizeof(PacketList));
                            } else {
                                (*pkt_list)->next = av_mallocz(sizeof(PacketList));
                                *pkt_list = (*pkt_list)->next;
                            }
                            h264_handle_packet_fu_a(&(*pkt_list)->pkt, rtp->playload, rtp->playload_size);
                            (*pkt_list)->pkt.dts = start->ext_dts;
                            (*pkt_list)->pkt.pts = start->ext_dts + start->ext_cts;
                            (*pkt_list)->pkt.stream_index = rs->stream_index;
                        } else {
                            h264_handle_packet_fu_a(&(*pkt_list)->pkt, rtp->playload, rtp->playload_size);
                        }
                        rtp_packet_free(rtp);
                        rs->buf[i % rs->buf_len] = NULL;
                        rs->packet_num--;
                    }
                    rs->seq = i;
                    start = NULL;
                }
            }
        } else {
            if (start) {
                /* Break fragment */
                break;
            }

            if (*pkt_list == NULL) {
                *pkt_list = av_mallocz(sizeof(PacketList));
            } else {
                (*pkt_list)->next = av_mallocz(sizeof(PacketList));
                *pkt_list = (*pkt_list)->next;
            }

            av_new_packet(&(*pkt_list)->pkt, cur->playload_size + sizeof(start_sequence));
            memcpy((*pkt_list)->pkt.data, start_sequence, sizeof(start_sequence));
            memcpy((*pkt_list)->pkt.data + sizeof(start_sequence), cur->playload, cur->playload_size);
            (*pkt_list)->pkt.dts = cur->ext_dts;
            (*pkt_list)->pkt.pts = cur->ext_dts + cur->ext_cts;
            (*pkt_list)->pkt.flags |= AV_PKT_FLAG_KEY;
            (*pkt_list)->pkt.stream_index = rs->stream_index;
            rs->seq = cur->seq + 1;
            rs->buf[cur->seq % rs->buf_len] = NULL;
            rtp_packet_free(cur);
            rs->packet_num--;
        }

        index++;
        cur = rs->buf[index % rs->buf_len];
    }
    return 0;
}

static int parse_rtp(uint8_t *buf, int size, RTPPacket *pkt)
{
    int cc = buf[0] & 0x0f;
    int ext = buf[0] & 0x10;
    pkt->seq = AV_RB16(buf+2);
    pkt->ts = AV_RB32(buf+4);
    int pos = 12 + cc * 4;
    if (ext) {
        if ((buf[pos] == 0xbe) && (buf[pos+1] == 0xde)) {
            /* One-byte extension */
            pos += 2;
            int len = (buf[pos] << 8) | buf[pos+1];
            pos += 2;
            for (int i = 0; i < len * 4;) {
                if (buf[pos+i] == 0) {
                    i++;
                    continue;
                }
                int id = (buf[pos+i] >> 4) & 0x0f;
                int l = buf[pos+i] & 0x0f;
                switch (id) {
                case DTS_EXTMAP:
                    for (int j = 0; j < l+1; j++) {
                        pkt->ext_dts = (buf[pos+i+1+j] << (8 * (l-j))) | pkt->ext_dts;
                    }
                    break;
                case CTS_EXTMAP:
                    for (int j = 0; j < l+1; j++) {
                        pkt->ext_cts = (buf[pos+i+1+j] << (8 * (l-j))) | pkt->ext_cts;
                    }
                    break;
                default:
                    break;
                }
                i += 1 + l + 1;
            }
            pos += len * 4;
        } else if ((buf[pos] == 0x10) && (((buf[pos+1] >> 4) & 0x0f) == 0)) {
            /* Two-byte extension */
            pos += 2;
            int len = buf[pos] << 8 | buf[pos+1];
            pos += 2;
            for (int i = 0; i < len*4;) {
                int id = buf[pos+i];
                int l = buf[pos+i+1];
                switch (id) {
                case DTS_EXTMAP:
                    for (int j = 0; j < l; j++) {
                        pkt->ext_dts = (buf[pos+i+2+j] << (8 * (l-j-1))) | pkt->ext_dts;
                    }
                    break;
                case CTS_EXTMAP:
                    for (int j = 0; j < l; j++) {
                        pkt->ext_cts = (buf[pos+i+2+j] << (8 * (l-j-1))) | pkt->ext_cts;
                    }
                    break;
                default:
                    break;
                }
                i += 2 + l;
            }
            pos += len * 4;
        }
    }

    pkt->playload_size = size - pos;
    pkt->playload = av_mallocz(pkt->playload_size);
    memcpy(pkt->playload, buf + pos, pkt->playload_size);
    return 0;
}

static void *read_rtp_thread(void *arg)
{
    WebrtcStreamContext *ctx = arg;
    int ret = 0;
    uint8_t buf[2048];

    for(;;) {
        ret = ffurl_read(ctx->rtp_hd, buf, sizeof(buf));
        int size = ret;
        if (is_rtp(buf, size)) {
            uint8_t pt = buf[1] & 0x7f;
            RTPStream *rs = rtp_stream_get(ctx, pt);
            if (!rs) {
                continue;
            }

            RTPPacket *rtp_pkt = rtp_packet_alloc();
            parse_rtp(buf, size, rtp_pkt);
            if (rs->type == AVMEDIA_TYPE_AUDIO) {
                AVPacket *pkt = av_packet_alloc();
                av_new_packet(pkt, rtp_pkt->playload_size);
                memcpy(pkt->data, rtp_pkt->playload, rtp_pkt->playload_size);
                pkt->dts = rtp_pkt->ext_dts;
                pkt->pts = rtp_pkt->ext_dts + rtp_pkt->ext_cts;
                pkt->flags |= AV_PKT_FLAG_KEY;
                pkt->stream_index = rs->stream_index;
                queue_put(&ctx->queue, pkt);
            } else if (rs->type == AVMEDIA_TYPE_VIDEO) {
                write_rtp_packet_to_buffer(rs, rtp_pkt);
                PacketList *pkt_list = NULL;
                read_avpackets_from_buffer(rs, &pkt_list);
                while (pkt_list) {
                    AVPacket *pkt = &pkt_list->pkt;
                    queue_put(&ctx->queue, pkt);
                    pkt_list = pkt_list->next;
                }
            }
        } else if (is_rtcp(buf, size)) {
            /* TODO: Handle rtcp packet */
        }

        int64_t cur = av_gettime();
        if (cur - ctx->last_bind_req_time > STUN_BINDING_INTERVAL * 1000) {
            uint8_t buf[256] = {0};
            int n = stun_write(buf, 256, ctx->stun_bind_req, STUN_BINDING_PASSWORD);
            ffurl_write(ctx->rtp_hd, buf, n);
            ctx->last_bind_req_time = cur;
        }
    }
}

static int webrtc_connect(AVFormatContext *s, const Candidate *candidate, const char *username)
{
    WebrtcStreamContext *ctx = s->priv_data;
    URLContext *h = NULL;
    uint8_t buf[256] = {0};
    stun_message_t *msg = av_mallocz(sizeof(stun_message_t));
    char url[256] = {0};
    int ret = 0;

    ff_url_join(url, sizeof(url), "udp", NULL, candidate->ip,
                candidate->port, "?localport=65510&fifo_size=0");
    av_log(s, AV_LOG_INFO, "Webrtc connect to %s, username = %s\n", url, username);
    if ((ret = ffurl_open_whitelist(&h, url, AVIO_FLAG_READ_WRITE,
                                    NULL, NULL, s->protocol_whitelist,
                                    s->protocol_blacklist, NULL)) < 0) {
        av_log(s, AV_LOG_ERROR, "Cannot open connection");
        return ret;
    }
    ctx->rtp_hd = h;

    queue_init(s, &ctx->queue);
    pthread_create(&ctx->thread, NULL, read_rtp_thread, ctx);

    msg->msg_class = STUN_CLASS_REQUEST;
    msg->msg_method = STUN_METHOD_BINDING; 
    msg->ice_controlling = 1;
    msg->priority = 1;
    msg->use_candidate = 1;
    memcpy(msg->credentials.username, username, strlen(username));
    for (int i = 0; i < sizeof(msg->transaction_id); i++) {
        msg->transaction_id[i] = i;
    }

    if ((ret = stun_write(buf, sizeof(buf), msg, STUN_BINDING_PASSWORD)) < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to make stun message");
        return AVERROR_UNKNOWN;
    }

    ctx->stun_bind_req = msg;
    ctx->last_bind_req_time = av_gettime();
    if ((ret = ffurl_write(h, buf, ret)) < 0) {
        av_log(s, AV_LOG_ERROR, "Webrtc connect candidate failed, %s\n", av_err2str(ret));
        return ret;
    }
    return 0;
}

static int parse_fmtp_config(AVStream *st, const char *value)
{
    int len = ff_hex_to_data(NULL, value), i, ret = 0;
    GetBitContext gb;
    uint8_t *config;
    int audio_mux_version, same_time_framing, num_programs, num_layers;

    /* Pad this buffer, too, to avoid out of bounds reads with get_bits below */
    config = av_mallocz(len + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!config)
        return AVERROR(ENOMEM);
    ff_hex_to_data(config, value);
    init_get_bits(&gb, config, len*8);
    audio_mux_version = get_bits(&gb, 1);
    same_time_framing = get_bits(&gb, 1);
    skip_bits(&gb, 6); /* num_sub_frames */
    num_programs      = get_bits(&gb, 4);
    num_layers        = get_bits(&gb, 3);
    if (audio_mux_version != 0 || same_time_framing != 1 || num_programs != 0 ||
        num_layers != 0) {
        avpriv_report_missing_feature(NULL, "LATM config (%d,%d,%d,%d)",
                                      audio_mux_version, same_time_framing,
                                      num_programs, num_layers);
        ret = AVERROR_PATCHWELCOME;
        goto end;
    }
    ret = ff_alloc_extradata(st->codecpar, (get_bits_left(&gb) + 7)/8);
    if (ret < 0) {
        goto end;
    }
    for (i = 0; i < st->codecpar->extradata_size; i++)
        st->codecpar->extradata[i] = get_bits(&gb, 8);

end:
    av_free(config);
    return ret;
}

static int create_streams_from_sdp(AVFormatContext *s, const SDP *sdp)
{
    WebrtcStreamContext *ctx = s->priv_data;
    for (int i = 0; i < sdp->nb_medias; i++) {
        RTPMedia *m = sdp->medias[i];
        switch (m->type) {
        case AVMEDIA_TYPE_AUDIO: {
            AVStream *st = avformat_new_stream(s, NULL);
            st->codecpar->codec_type = m->type;
            // TODO: get audio codec from sdp
            st->codecpar->codec_id = AV_CODEC_ID_AAC;
            st->codecpar->channels = m->channel;
            st->codecpar->sample_rate = m->sample_rate;
            parse_fmtp_config(st, m->config);
            /* Get PTS from rtp extend header, so set 1000 as sample rate */
            avpriv_set_pts_info(st, 32, 1, 1000);

            RTPStream *rs = rtp_stream_create(ctx);
            rs->stream_index = st->index;
            rs->pt = m->pt;
            rs->type = m->type;

            av_log(s, AV_LOG_DEBUG, "Media channels=%d sample_rate=%d extradata=%s extradata_size=%d\n",
                st->codecpar->channels, st->codecpar->sample_rate,
                st->codecpar->extradata, st->codecpar->extradata_size);
            break;
        }
        case AVMEDIA_TYPE_VIDEO: {
            AVStream *st = avformat_new_stream(s, NULL);
            st->codecpar->codec_type = m->type;
            st->codecpar->codec_id = AV_CODEC_ID_H264;
            avpriv_set_pts_info(st, 32, 1, 1000);

            RTPStream *rs = rtp_stream_create(ctx);
            rs->stream_index = st->index;
            rs->pt = m->pt;
            rs->type = m->type;
            break;
        }
        default:
            break;
        }
    }
    return 0;
}

static int webrtc_stream_read_header(AVFormatContext *s)
{
    int ret = 0;
    uint8_t buf[16 * 1024] = {0};
    int n = 0, buf_size = sizeof(buf);
    WebrtcStreamContext *c = s->priv_data;
    URLContext *h = NULL;
    char *username = NULL;
    Answer *ans = NULL;

    c->s = s;
    if (c->api == NULL) {
        av_log(s, AV_LOG_ERROR, "Option api not found\n");
        return AVERROR_OPTION_NOT_FOUND;
    }

    c->answer = av_mallocz(sizeof(Answer));
    ans = c->answer;

    if ((ret = send_offer(&h, s, c->api, OFFER_SDP)) < 0) {
        av_log(s, AV_LOG_ERROR, "Send offer failed\n");
        ffurl_close(h);
        return ret;
    }
    av_log(s, AV_LOG_DEBUG, "Send offer %s to %s\n", OFFER_SDP, c->api);

    while (n < buf_size) {
        int ret = ffurl_read(h, buf + n, buf_size - n);
        if (ret <= 0) {
            break;
        }
        n += ret;
    }
    ffurl_close(h);
    av_log(s, AV_LOG_DEBUG, "Got answer %s\n", buf);

    if (parse_answer(ans, buf) < 0) {
        av_log(s, AV_LOG_ERROR, "Parse answer failed\n");
        return AVERROR_INVALIDDATA;
    }

    create_streams_from_sdp(s, &ans->sdp);

    username = av_asprintf("%s:%s", ans->sdp.ice_ufrag, LOCAL_ICE_UFRAG);
    if ((ret = webrtc_connect(s, &ans->sdp.candidate, username) != 0)) {
        av_log(s, AV_LOG_ERROR, "Webrtc connect failed\n");
        av_free(username);
        return ret;
    }
    av_free(username);
    return ret;
}

static int webrtc_stream_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    WebrtcStreamContext *h = s->priv_data;
    int ret = queue_get(&h->queue, pkt, 1);
    return ret > 0 ? 0 : ret;
}

static int webrtc_stream_read_close(AVFormatContext *s)
{
    webrtc_stream_close(s);
    return 0;
}

#define OFFSET(x) offsetof(WebrtcStreamContext, x)

static const AVOption options[] = {
    {"api", "HTTP signaling API",
        OFFSET(api), AV_OPT_TYPE_STRING,
        {.str = NULL},
        0, 0, AV_OPT_FLAG_DECODING_PARAM},
    { NULL },
};

static const AVClass webrtc_stream_class = {
    .class_name = "webrtc stream",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVInputFormat ff_webrtc_stream_demuxer = {
    .name           = "webrtc stream",
    .long_name      = "webrtc stream demuxer",
    .priv_data_size = sizeof(WebrtcStreamContext),
    .read_probe     = webrtc_stream_probe,
    .read_header    = webrtc_stream_read_header,
    .read_packet    = webrtc_stream_read_packet,
    .read_close     = webrtc_stream_read_close,
    .extensions      = "webrtc",
    .priv_class     = &webrtc_stream_class,
    .flags          = AVFMT_NOFILE,
};

#ifdef BUILD_AS_PLUGIN
void register_webrtc_stream_demuxer()
{
    av_log(NULL, AV_LOG_INFO, "register webrtc_stream_demuxer\n");
    av_register_input_format(&ff_webrtc_stream_demuxer);
}
#endif
