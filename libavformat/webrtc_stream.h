#ifndef WEBRTC_STREAM_H
#define WEBRTC_STREAM_H
#include "libavutil/log.h"
#include "libavformat/url.h"

#include "stun.h"

typedef struct PacketList {
    struct PacketList *next;
    AVPacket pkt;
} PacketList;

typedef struct AVPacketQueue {
    PacketList *first_pkt, *last_pkt;
    int nb_packets;
    unsigned long long size;
    int abort_request;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    AVFormatContext *avctx;
    int64_t max_q_size;
} AVPacketQueue;

typedef struct Candidate {
    char ip[64];
    uint16_t port;
} Candidate;

typedef struct RTPMedia {
    int id;
    enum AVMediaType type;

    // Audio info
    int channel;
    int sample_rate;
    int audio_pl_id; // audio profile level id
    int object;
    int ps;
    int sbr;
    char config[128];

    // Video info
    int bframe_enabled;
    int level_asymmetry_allowed;
    int packetization_mode;
    char video_pl_id[128]; // video profile level id
} RTPMedia;

// TODO: free
typedef struct SDP {
    char ice_ufrag[64];

    // TODO: support multi candidate
    Candidate candidate;

    RTPMedia **medias;
    uint32_t nb_medias;
} SDP;

typedef struct Offer {
    char stream_url[1024];
    SDP sdp;
} Offer;

typedef struct Answer {
    SDP sdp;
} Answer;

typedef struct WebrtcStreamContext {
    const AVClass *class;
    AVFormatContext *s;

    char *api;
    char *offer_file;

    URLContext *rtp_hd;
    pthread_t thread;
    AVPacketQueue queue;
    AVStream *stream_index[256];
    SDP *answer_sdp;
    AVPacket *unfinished_pkt;

    stun_message_t *stun_bind_req;
    int64_t last_bind_req_time;
} WebrtcStreamContext;
#endif // WEBRTC_STREAM_H