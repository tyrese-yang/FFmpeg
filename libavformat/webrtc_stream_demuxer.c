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

#include "webrtc_stream.h"

#define STUN_BINDING_INTERVAL 2000 // ms
#define STUN_BINDING_PASSWORD "ffmpeg"
#define LOCAL_ICE_UFRAG "ffmpeg"

const char *SDP_STR = "v=0\r\n"
    "o=- 4081582919824265660 2 IN IP4 127.0.0.1\r\n"
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
    "a=rtcp-fb:96 goog-remb\r\n"
    "a=rtcp-fb:96 transport-cc\r\n"
    "a=rtcp-fb:96 ccm fir\r\n"
    "a=rtcp-fb:96 nack\r\n"
    "a=rtcp-fb:96 nack pli\r\n"
    "a=rtcp-fb:96 rrtr\r\n"
    "a=fmtp:96 bframe-enabled=1;level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f\r\n"
    "a=rtpmap:97 rtx/90000\r\n"
    "a=fmtp:97 apt=96\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    "a=rtcp-fb:98 goog-remb\r\n"
    "a=rtcp-fb:98 transport-cc\r\n"
    "a=rtcp-fb:98 ccm fir\r\n"
    "a=rtcp-fb:98 nack\r\n"
    "a=rtcp-fb:98 nack pli\r\n"
    "a=rtcp-fb:98 rrtr\r\n"
    "a=fmtp:98 bframe-enabled=1;level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
    "a=rtpmap:99 rtx/90000\r\n"
    "a=fmtp:99 apt=98\r\n"
    "a=rtpmap:100 red/90000\r\n"
    "a=rtpmap:101 rtx/90000\r\n"
    "a=fmtp:101 apt=100\r\n"
    "a=rtpmap:102 ulpfec/90000\r\n";

static int webrtc_open(AVFormatContext *h, const char *uri)
{
    av_log(h, AV_LOG_INFO, "webrtc_stream_open exit\n");
    return 0;
}

static int webrtc_stream_close(AVFormatContext *h)
{
    av_log(h, AV_LOG_INFO, "webrtc_stream_close exit\n");
    return 0;
}

static int webrtc_stream_probe(AVProbeData *p)
{
    if (av_strstart(p->filename, "webrtc:", NULL))
        return AVPROBE_SCORE_MAX;
    return 0;
}

static RTPMedia *rtp_media_create(SDP *sdp)
{
    av_log(NULL, AV_LOG_DEBUG, "m=%p n=%d\n", sdp->medias, sdp->nb_medias + 1);
    RTPMedia **medias = av_realloc_array(sdp->medias, sdp->nb_medias + 1, sizeof(*medias));
    sdp->medias = medias;
    RTPMedia *m = av_malloc(sizeof(RTPMedia));
    sdp->medias[sdp->nb_medias++] = m;
    return m;
}

static RTPMedia *get_media(const SDP *sdp, uint32_t id)
{
    for (int i = 0; i < sdp->nb_medias; i++) {
        if (sdp->medias[i]->id == id) {
            return sdp->medias[i];
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

    // Drop Packet if queue size is > maximum queue size
    if (queue_size(q) > (uint64_t)q->max_q_size) {
        av_packet_unref(pkt);
        av_log(q->avctx, AV_LOG_WARNING,  "Decklink input buffer overrun!\n");
        return -1;
    }
    /* ensure the packet is reference counted */
    if (av_packet_make_refcounted(pkt) < 0) {
        av_packet_unref(pkt);
        return -1;
    }

    pkt1 = (PacketList *)av_malloc(sizeof(PacketList));
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

static int read_file(const char *filename, uint8_t *buf, int size)
{
    FILE *f = fopen(filename, "r");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    int n = fread(buf, 1, fsize, f);
    fclose(f);
    return n;
}

static int send_offer(AVFormatContext *s, const char* uri, uint8_t *answer, int answer_size)
{
    uint8_t buf[16*1024] = {0};
    const char *fmt = "{\"clientinfo\":\"ffmpeg\","
                        "\"sessionid\":\"1\","
                        "\"streamurl\":\"%s\","
                        "\"localsdp\":{"
                            "\"type\":\"offer\","
                            "\"sdp\":\"%s\""
                        "}}";
    sprintf(buf, fmt, s->url, SDP_STR);

    URLContext *h = NULL;
    ffurl_alloc(&h, uri, AVIO_FLAG_READ_WRITE, NULL);
    av_opt_set_bin(h->priv_data, "post_data", buf, strlen(buf), 0);

    av_log(s, AV_LOG_INFO, "send offer %s to %s\n", buf, uri);

    ffurl_connect(h, NULL);
    int n = 0;
    while (n < answer_size) {
        int ret = ffurl_read(h, answer+n, answer_size-n);
        if (ret <= 0) {
            break;
        }
        n += ret;
    }

    ffurl_close(h);
    return 0;
}

static char *read_line_arg(const char *data, const char *split, char *buf)
{
    char *next = av_stristr(data, split);
    if (buf) {
        if (next)
            memcpy(buf, data, next - data);
        else
            strcpy(buf, data);
    }
    return next ? next + 1 : NULL;
}

static int parse_attr(const char *line, int len, SDP *sdp)
{
    char *v = NULL;
    if (av_strstart(line, "a=ice-ufrag:", &v)) {
        memcpy(sdp->ice_ufrag, v, len - (v - line));
    } else if (av_strstart(line, "a=candidate:", &v)) {
        // a=candidate:foundation 1 udp 100 27.159.95.33 8000 typ srflx raddr 27.159.95.33 rport 8000 generation 0
        // TODO: do not use sscanf
        sscanf(v, "%*s %*d %*s %*d %s %d %*s", sdp->candidate.ip, &sdp->candidate.port);
    } else if (av_strstart(line, "a=fmtp:", &v)) {
        // a=fmtp:123 PS-enabled=0;SBR-enabled=0;config=40002420adca1fe0;cpresent=0;object=2;profile-level-id=1;stereo=1
        int l = 0;
        l = av_stristr(v, " ") - v;
        char buf[128] = {0};
        memcpy(buf, v, l);
        int id = atoi(buf);
        RTPMedia *m = get_media(sdp, id);
        if (m) {
            switch (m->type) {
            case AVMEDIA_TYPE_AUDIO: {
                v += l + 1;
                char *next = v;
                while(1) {
                    memset(buf, 0, sizeof(buf));
                    next = read_line_arg(next, ";", buf);
                    char *vv;
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
                    if (!next) {
                        break;
                    }
                }
                break;
            }
            case AVMEDIA_TYPE_VIDEO:{
                v += l + 1;
                char *next = v;
                while(1) {
                    memset(buf, 0, sizeof(buf));
                    next = read_line_arg(next, ";", buf);
                    char *vv;
                    if (av_stristart(buf, "bframe-enabled=", &vv)) {
                        m->bframe_enabled = atoi(vv);
                    } else if (av_stristart(buf, "level-asymmetry-allowed=", &vv)) {
                        m->level_asymmetry_allowed = atoi(vv);
                    } else if (av_stristart(buf, "packetization-mode=", &vv)) {
                        m->packetization_mode = atoi(vv);
                    } else if (av_stristart(buf, "profile-level-id=", &vv)) {
                        memcpy(m->video_pl_id, vv, strlen(vv));
                    }
                    if (!next) {
                        break;
                    }
                }
                av_log(NULL, AV_LOG_DEBUG, "bf=%d laa=%d pli=%s\n", m->bframe_enabled, m->level_asymmetry_allowed, m->video_pl_id);
                break;
            }
            default:
                break;
            }
        }
    } else if (av_strstart(line, "a=rtpmap:", &v)) {
        // a=rtpmap:123 MP4A-ADTS/44100/2
        int l = 0;
        l = av_stristr(v, " ") - v;
        char buf[128] = {0};
        memcpy(buf, v, l);
        int id = atoi(buf);
        RTPMedia *m = get_media(sdp, id);
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
                av_log(NULL, AV_LOG_DEBUG, "channel=%d sample_rate=%d\n", v, channel, sample_rate);
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

static int parse_mline(const char *line, int len, SDP *sdp)
{
    if (av_strstart(line, "m=audio", NULL)) {
        // m=audio 1 RTP/AVPF 123
        char *next = read_line_arg(line, " ", NULL);
        if (next)
            next = read_line_arg(next, " ", NULL);
        if (next)
            next = read_line_arg(next, " ", NULL);
        while (next) {
            char buf[8] = {0};
            next = read_line_arg(next, " ", buf);
            RTPMedia *m = rtp_media_create(sdp);
            m->id = atoi(buf);
            m->type = AVMEDIA_TYPE_AUDIO;
        }
    } else if (av_strstart(line, "m=video", NULL)) {
        char *next = read_line_arg(line, " ", NULL);
        if (next)
            next = read_line_arg(next, " ", NULL);
        if (next)
            next = read_line_arg(next, " ", NULL);
        while (next) {
            char buf[8] = {0};
            next = read_line_arg(next, " ", buf);
            RTPMedia *m = rtp_media_create(sdp);
            m->id = atoi(buf);
            m->type = AVMEDIA_TYPE_VIDEO;
        }
    }
    return 0;
}

static int parse_line(const char *line, int len, SDP *sdp)
{
    char buf[256] = {0};
    memcpy(buf, line, len);
    av_log(NULL, AV_LOG_DEBUG, "parse line %s\n", buf);
    switch(line[0]) {
    case 'a':
        return parse_attr(buf, len, sdp);
    case 'm':
        return parse_mline(buf, len, sdp);
    default:
        return 0;
    }
    return 0;
}

static int parse_sdp(const char *data, int size, SDP *sdp)
{
    char *pos = data;
    char *line_end = NULL;
    int len = 0;
    if ((line_end = av_stristr(pos, "\\r"))
        || (line_end = av_stristr(pos, "\\n"))
        || (line_end = av_stristr(pos, "\r"))
        || (line_end = av_stristr(pos, "\n"))) {

        len = line_end ? line_end - pos : size;
    }
    // av_log(NULL, AV_LOG_INFO, "pos:%p, len:%d\n", pos, len);
    while (1 && len > 0) {
        if (parse_line(pos, len, sdp) < 0) {
            return -1;
        }
        // next line
        pos += len;
        char *eq = strchr(pos, '=');
        if (!eq) {
            break;
        }
        pos = eq - 1;
        len = 0;
         if ((line_end = av_stristr(pos, "\\r"))
            || (line_end = av_stristr(pos, "\\n"))
            || (line_end = av_stristr(pos, "\r"))
            || (line_end = av_stristr(pos, "\n"))) {

            len = line_end ? line_end - pos : size;
        }
    }
    return 0;
}

static int parse_answer(const char *data, int size, Answer *answer)
{
    char *pos = av_stristr(data, "\"sdp\":");
    pos+=strlen("\"sdp\":");
    pos = av_stristr(pos, "\"");
    pos+=1;
    parse_sdp(pos, size - (pos - data), &answer->sdp);
    return 0;
}

static int is_rtp(const char *data, int size)
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

static int is_rtcp(const char *data, int size)
{
    return (size > 12) && (data[0] & 0x80) && (data[1] >= 192 && data[1] <= 223);
}

#define NAL_MASK 0x1f
static const uint8_t start_sequence[] = { 0, 0, 0, 1 };

static int h264_handle_frag_packet(AVPacket *pkt, const uint8_t *buf, int len,
                               int start_bit, const uint8_t *nal_header,
                               int nal_header_len)
{
    int ret;
    int tot_len = len;
    int pos = 0;
    if (start_bit)
        tot_len += sizeof(start_sequence) + nal_header_len;
    if ((ret = av_new_packet(pkt, tot_len)) < 0)
        return ret;
    if (start_bit) {
        memcpy(pkt->data + pos, start_sequence, sizeof(start_sequence));
        pos += sizeof(start_sequence);
        memcpy(pkt->data + pos, nal_header, nal_header_len);
        pos += nal_header_len;
    }
    memcpy(pkt->data + pos, buf, len);
    return 0;
}

static int h264_handle_packet_fu_a(AVFormatContext *ctx, void *data, AVPacket *pkt,
                                   const uint8_t *buf, int len, uint32_t dts, uint32_t cts)
{
    if (len < 3) {
        av_log(ctx, AV_LOG_ERROR, "Too short data for FU-A H.264 RTP packet\n");
        return AVERROR_INVALIDDATA;
    }
    
    uint8_t fu_indicator = buf[0];
    uint8_t fu_header    = buf[1];
    uint8_t start_bit    = fu_header >> 7;
    uint8_t end_bit      = (fu_header >> 6) & 0x01;
    uint8_t nal_type     = fu_header & 0x1f;
    uint8_t nal_header   = fu_indicator & 0xe0 | nal_type;
    uint8_t nal_header_len = 1;

    // skip the fu_indicator and fu_header
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
        pkt->dts = dts;
        pkt->pts = dts + cts;
    } else {
        pos = pkt->size;
        if ((ret = av_grow_packet(pkt, len)) < 0)
            return ret;
        memcpy(pkt->data + pos, buf, len);
    }

    if (end_bit) {
        return 0;
    }
    return pkt->size;
}

static int h264_handle_aggregated_packet(AVFormatContext *ctx, void *data, AVPacket *pkt,
                                     const uint8_t *buf, int len,
                                     int skip_between, int *nal_counters,
                                     int nal_mask, uint32_t dts, uint32_t cts)
{
    int pass         = 0;
    int total_length = 0;
    uint8_t *dst     = NULL;
    int ret;

    // first we are going to figure out the total size
    for (pass = 0; pass < 2; pass++) {
        const uint8_t *src = buf;
        int src_len        = len;

        while (src_len > 2) {
            uint16_t nal_size = AV_RB16(src);

            // consume the length of the aggregate
            src     += 2;
            src_len -= 2;

            if (nal_size <= src_len) {
                if (pass == 0) {
                    // counting
                    total_length += sizeof(start_sequence) + nal_size;
                } else {
                    // copying
                    memcpy(dst, start_sequence, sizeof(start_sequence));
                    dst += sizeof(start_sequence);
                    memcpy(dst, src, nal_size);
                    if (nal_counters)
                        nal_counters[(*src) & nal_mask]++;
                    dst += nal_size;
                }
            } else {
                av_log(ctx, AV_LOG_ERROR,
                       "nal size exceeds length: %d %d\n", nal_size, src_len);
                return AVERROR_INVALIDDATA;
            }

            // eat what we handled
            src     += nal_size + skip_between;
            src_len -= nal_size + skip_between;
        }

        if (pass == 0) {
            /* now we know the total size of the packet (with the
             * start sequences added) */
            if ((ret = av_new_packet(pkt, total_length)) < 0)
                return ret;
            dst = pkt->data;
            pkt->dts = dts;
            pkt->pts = dts + cts;
        }
    }

    return 0;
}

static int handle_audio_payload(AVFormatContext *s, AVPacket **pkt, const uint8_t *buf, int size)
{
    *pkt = av_packet_alloc();
    av_new_packet(*pkt, size);
    memcpy((*pkt)->data, buf, size);
    return 0;
}

// return 0 is finished packet
static int handle_video_payload(AVFormatContext *ctx, AVPacket **unfinished_pkt,
                                const uint8_t *buf, int len, uint32_t dts, uint32_t cts)
{
    uint8_t nal;
    uint8_t type;
    int result = 0;

    if (!len) {
        av_log(ctx, AV_LOG_ERROR, "Empty H.264 RTP packet\n");
        return AVERROR_INVALIDDATA;
    }
    nal  = buf[0];
    type = nal & 0x1f;

    /* Simplify the case (these are all the NAL types used internally by
     * the H.264 codec). */
    if (type >= 1 && type <= 23)
        type = 1;

    if (*unfinished_pkt == NULL) {
        *unfinished_pkt = av_packet_alloc();
    }
    AVPacket *pkt = *unfinished_pkt;

    switch (type) {
    case 0:                    // undefined, but pass them through
    case 1:
    case 31: // private type
        if ((result = av_new_packet(pkt, len + sizeof(start_sequence))) < 0)
            return result;
        pkt->dts = dts;
        pkt->pts = dts + cts;
        memcpy(pkt->data, start_sequence, sizeof(start_sequence));
        memcpy(pkt->data + sizeof(start_sequence), buf, len);
        break;

    case 24:                   // STAP-A (one packet, multiple nals)
        // consume the STAP-A NAL
        buf++;
        len--;
        result = h264_handle_aggregated_packet(ctx, NULL, pkt, buf, len, 0,
                                                  NULL, NAL_MASK, dts, cts);
        break;

    case 25:                   // STAP-B
    case 26:                   // MTAP-16
    case 27:                   // MTAP-24
    case 29:                   // FU-B
        avpriv_report_missing_feature(ctx, "RTP H.264 NAL unit type %d", type);
        result = AVERROR_PATCHWELCOME;
        break;

    case 28:                   // FU-A (fragmented nal)
        result = h264_handle_packet_fu_a(ctx, NULL, pkt, buf, len, dts, cts);
        break;

    case 30:                   // undefined
    default:
        av_log(ctx, AV_LOG_ERROR, "Undefined type (%d)\n", type);
        result = AVERROR_INVALIDDATA;
        break;
    }

    return result;
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
            int pt = buf[1] & 0x7f;
            int cc = buf[0] & 0x0f;
            int ext = buf[0] & 0x10;
            uint16_t seq = AV_RB16(buf+2);
            uint32_t ts = AV_RB32(buf+4);
            int pos = 12 + cc * 4;
            uint32_t dts = 0;
            uint32_t cts = 0;
            if (ext) {
                if ((buf[pos] == 0xbe) && (buf[pos+1] == 0xde)) {
                    // ony-byte extension
                    pos += 2;
                    int len = (buf[pos] << 8) | buf[pos+1];
                    pos += 2;
                    for (int i = 0; i < len * 4;) {
                        if (buf[pos+i] == 0) {
                            i++;
                            continue;
                        }
                        int id = (buf[pos+i] > 4) & 0x0f;
                        int l = buf[pos+i] & 0x0f;
                        switch (id) {
                        case 10:
                            for (int j = 0; j < l+1; j++) {
                                dts = (buf[pos+i+1+j] << (8 * (l-j))) | dts;
                            }
                            break;
                        case 18:
                            for (int j = 0; j < l+1; j++) {
                                cts = (buf[pos+i+1+j] << (8 * (l-j))) | cts;
                            }
                            break;
                        default:
                            break;
                        }
                        i += 1 + l + 1;
                    }
                    pos += len * 4;
                } else if ((buf[pos] == 0x10) && (((buf[pos+1] >> 4) & 0x0f) == 0)) {
                    // two-byte extension
                    pos += 2;
                    int len = buf[pos] << 8 | buf[pos+1];
                    pos += 2;
                    for (int i = 0; i < len*4;) {
                        int id = buf[pos+i];
                        int l = buf[pos+i+1];
                        switch (id) {
                        case 10:
                            for (int j = 0; j < l; j++) {
                                dts = (buf[pos+i+2+j] << (8 * (l-j-1))) | dts;
                            }
                            break;
                        case 18:
                            for (int j = 0; j < l; j++) {
                                cts = (buf[pos+i+2+j] << (8 * (l-j-1))) | cts;
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

            RTPMedia *m = get_media(ctx->answer_sdp, pt);
            if (m) {
                int payload_size = size - pos;
                AVPacket *pkt = NULL;
                uint8_t *payload = buf + pos;
                if (m->type == AVMEDIA_TYPE_AUDIO) {
                    handle_audio_payload(ctx->s, &pkt, payload, payload_size);
                    pkt->dts = dts;
                    pkt->pts = dts+cts;
                } else if (m->type == AVMEDIA_TYPE_VIDEO) {
                    if (handle_video_payload(ctx->s, &ctx->unfinished_pkt, payload, payload_size, dts, cts) == 0) {
                        pkt = ctx->unfinished_pkt;
                        ctx->unfinished_pkt = NULL;
                    }
                }
                if (pkt) {
                    pkt->stream_index = ctx->stream_index[pt] ? ctx->stream_index[pt]->index : 0;
                    queue_put(&ctx->queue, pkt);
                }
            }
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
    char url[256] = {0};
    ff_url_join(url, sizeof(url), "udp", NULL, candidate->ip, candidate->port, "?localport=65510&fifo_size=0");
    av_log(s, AV_LOG_INFO, "webrtc connect %s, username = %s\n", url, username);
    int ret = ffurl_open_whitelist(&h, url,
                    AVIO_FLAG_READ_WRITE, NULL, NULL, s->protocol_whitelist, s->protocol_blacklist, NULL);
    ctx->rtp_hd = h;

    queue_init(s, &ctx->queue);
    pthread_create(&ctx->thread, NULL, read_rtp_thread, ctx);

    uint8_t buf[256] = {0};
    stun_message_t *msg = av_malloc(sizeof(stun_message_t));
    memset(msg, 0, sizeof(stun_message_t));
    msg->msg_class = STUN_CLASS_REQUEST;
    msg->msg_method = STUN_METHOD_BINDING; 
    msg->ice_controlling = 1;
    msg->priority = 1;
    memcpy(msg->credentials.username, username, strlen(username));
    for (int i = 0; i < sizeof(msg->transaction_id); i++) {
        msg->transaction_id[i] = i;
    }
    ret = stun_write(buf, 256, msg, STUN_BINDING_PASSWORD);
    ctx->stun_bind_req = msg;
    ctx->last_bind_req_time = av_gettime();
    ret = ffurl_write(h, buf, ret);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "webrtc connect candidate failed, %s\n", ret, av_err2str(ret));
    }
    return 0;
}

static int create_streams_from_sdp(AVFormatContext *s, const SDP *sdp)
{
    for (int i = 0; i < sdp->nb_medias; i++) {
        RTPMedia *m = sdp->medias[i];
        switch (m->type) {
        case AVMEDIA_TYPE_AUDIO: {
            AVStream *st = avformat_new_stream(s, NULL);
            WebrtcStreamContext *ctx = s->priv_data;
            st->codecpar->codec_type = m->type;
            // TODO: get audio codec from sdp
            st->codecpar->codec_id = AV_CODEC_ID_AAC;
            st->codecpar->channels = m->channel;
            st->codecpar->sample_rate = m->sample_rate;
            /* decode the hexa encoded parameter */
            int len = ff_hex_to_data(NULL, m->config);
            ff_alloc_extradata(st->codecpar, len);
            ff_hex_to_data(st->codecpar->extradata, m->config);
            // avpriv_set_pts_info(st, 32, 1, st->codecpar->sample_rate);
            avpriv_set_pts_info(st, 32, 1, 1000);

            ctx->stream_index[m->id] = st;
            av_log(s, AV_LOG_DEBUG, "media channels=%d sample_rate=%d extradata=%s extradata_size=%d\n",
                st->codecpar->channels, st->codecpar->sample_rate,
                st->codecpar->extradata, st->codecpar->extradata_size);
            break;
        }
        case AVMEDIA_TYPE_VIDEO: {
            AVStream *st = avformat_new_stream(s, NULL);
            WebrtcStreamContext *ctx = s->priv_data;
            st->codecpar->codec_type = m->type;
            st->codecpar->codec_id = AV_CODEC_ID_H264;
            ctx->stream_index[m->id] = st;
            // avpriv_set_pts_info(st, 32, 1, 90000);
            avpriv_set_pts_info(st, 32, 1, 1000);
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
    Answer answer;
    memset(&answer, 0, sizeof(Answer));
    int ret = 0;
    uint8_t answer_buf[16*1024] = {0};
    WebrtcStreamContext *c = s->priv_data;
    // TODO: init context func
    c->s = s;
    int n = 0;

    if ((n = send_offer(s, c->api, answer_buf, sizeof(answer_buf))) != 0) {
        return -1;
    }
    av_log(s, AV_LOG_INFO, "got answer %s\n", answer_buf);

    if (parse_answer(answer_buf, n, &answer) != 0) {
        return -1;
    }

    create_streams_from_sdp(s, &answer.sdp);
    c->answer_sdp = av_malloc(sizeof(SDP));
    memcpy(c->answer_sdp, &answer.sdp, sizeof(SDP));

    char username[128] = {0};
    memcpy(username, answer.sdp.ice_ufrag, strlen(answer.sdp.ice_ufrag));
    username[strlen(answer.sdp.ice_ufrag)] = ':';
    memcpy(username+strlen(answer.sdp.ice_ufrag)+1, LOCAL_ICE_UFRAG, strlen(LOCAL_ICE_UFRAG));
    if ((ret = webrtc_connect(s, &answer.sdp.candidate, username) != 0)) {
        return ret;
    }
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
    {"api", "Pull stream API",
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
