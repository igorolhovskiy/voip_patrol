// #define PJ_IOQUEUE_MAX_HANDLES 1024
// #define FD_SETSIZE PJ_IOQUEUE_MAX_HANDLES
//
//
#define PJ_IOQUEUE_MAX_HANDLES      1024
#define FD_SETSIZE_SETABLE      1
#define __FD_SETSIZE            1024

#define PJSIP_MAX_TRANSPORTS        32
#define PJSIP_MAX_RESOLVED_ADDRESSES    32

#define PJSUA_MAX_ACC       512
#define PJSUA_MAX_CALLS     512
#define PJSUA_MAX_PLAYERS   512

// SRTP
#define PJMEDIA_SRTP_HAS_DTLS           1
// Make send of "100 - Trying" explicit
#define PJSUA_DISABLE_AUTO_SEND_100 1
// Disable detection of merged requests
// Personal fork define name
# define PJSUA_DETECT_MERGED_REQUEST    0
// Upstream project define name
# define PJSUA_DETECT_MERGED_REQUESTS   0
