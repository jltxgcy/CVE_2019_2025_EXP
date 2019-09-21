#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/IPCThreadState.h>
#include <media/IMediaPlayer.h>
#include <media/IMediaPlayerService.h>
#include <media/mediaplayer.h>
using namespace android;

enum {
    DISCONNECT = IBinder::FIRST_CALL_TRANSACTION,
    SET_DATA_SOURCE_URL,
    SET_DATA_SOURCE_FD,
    SET_DATA_SOURCE_STREAM,
    SET_DATA_SOURCE_CALLBACK,
    SET_BUFFERING_SETTINGS,
    GET_BUFFERING_SETTINGS,
    PREPARE_ASYNC,
    START,
    STOP,
    IS_PLAYING,
    SET_PLAYBACK_SETTINGS,
    GET_PLAYBACK_SETTINGS,
    SET_SYNC_SETTINGS,
    GET_SYNC_SETTINGS,
    PAUSE,
    SEEK_TO,
    GET_CURRENT_POSITION,
    GET_DURATION,
    RESET,
    NOTIFY_AT,
    SET_AUDIO_STREAM_TYPE,
    SET_LOOPING,
    SET_VOLUME,
    INVOKE,
    SET_METADATA_FILTER,
    GET_METADATA,
    SET_AUX_EFFECT_SEND_LEVEL,
    ATTACH_AUX_EFFECT,
    SET_VIDEO_SURFACETEXTURE,
    SET_PARAMETER,
    GET_PARAMETER,
    SET_RETRANSMIT_ENDPOINT,
    GET_RETRANSMIT_ENDPOINT,
    SET_NEXT_PLAYER,
    APPLY_VOLUME_SHAPER,
    GET_VOLUME_SHAPER_STATE,
    // Modular DRM
    PREPARE_DRM,
    RELEASE_DRM,
    // AudioRouting
    SET_OUTPUT_DEVICE,
    GET_ROUTED_DEVICE_ID,
    ENABLE_AUDIO_DEVICE_CALLBACK,
};
