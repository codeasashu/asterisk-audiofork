/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2019, Nadir Hamid
 * Copyright (C) 2005 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 * Kevin P. Fleming <kpfleming@digium.com>
 *
 * Based on app_muxmon.c provided by
 * Anthony Minessale II <anthmct@yahoo.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief AudioSync() - Offload Asterisk audio processing to a My server.
 * \ingroup applications
 *
 * \author Ashutosh Chaudhary <216.ashutosh@gmail.com>
 *
 * \note Based on app_mixmonitor.c provided by
 * asterisk
 */

/*** MODULEINFO
        <use type="module">func_periodic_hook</use>
        <support_level>core</support_level>
 ***/

#ifndef AST_MODULE
#define AST_MODULE "Audiosync"
#endif

#include "asterisk.h"

#include "asterisk/app.h"
#include "asterisk/audiohook.h"
#include "asterisk/autochan.h"
#include "asterisk/beep.h"
#include "asterisk/callerid.h"
#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/file.h"
#include "asterisk/format_cache.h"
#include "asterisk/linkedlists.h"
#include "asterisk/manager.h"
#include "asterisk/mod_format.h"
#include "asterisk/module.h"
#include "asterisk/paths.h" /* use ast_config_AST_MONITOR_DIR */
#include "asterisk/pbx.h"
#include "asterisk/stringfields.h"
#include "asterisk/test.h"

#include "asterisk/astobj2.h"
#include "asterisk/http_websocket.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/tcptls.h"

/*** DOCUMENTATION
        <application name="audiosync" language="en_US">
                <synopsis>
                        Sync a raw audio stream to a my file.
                </synopsis>
                <syntax>
                        <parameter name="options">
                                <optionlist>
                                        <option name="r">
                                                <argument name="file"
 required="true" /> <para>Use the specified file to record the
 <emphasis>receive</emphasis> audio feed. Like with the basic filename argument,
 if an absolute path isn't given, it will create the file in the configured
 monitoring directory.</para>
                                        </option>
                                        <option name="t">
                                                <argument name="file"
 required="true" /> <para>Use the specified file to record the
 <emphasis>transmit</emphasis> audio feed. Like with the basic filename
 argument, if an absolute path isn't given, it will create the file in the
 configured monitoring directory.</para>
                                        </option>
                                </optionlist>
                        </parameter>
                </syntax>
                <description>
                        <para>Forks raw audio to a my file.</para>
                </description>
        </application>
 ***/

#define SAMPLES_PER_FRAME 160
#define get_volfactor(x) x ? ((x > 0) ? (1 << x) : ((1 << abs(x)) * -1)) : 0

static const char *const app = "audiosync";

static const char *const stop_app = "Stopaudiosync";

static const char *const audiosync_spy_type = "audiosync";

struct audiosync {
  struct ast_audiohook audiohook;
  char *wsserver;
  enum ast_audiohook_direction direction;
  const char *direction_string;
  char *name;
  ast_callid callid;
  unsigned int flags;
  struct ast_autochan *autochan;
  struct audiosync_ds *audiosync_ds;

  /* the below string fields describe data used for creating voicemails from the
   * recording */
  AST_DECLARE_STRING_FIELDS(AST_STRING_FIELD(call_context);
                            AST_STRING_FIELD(call_macrocontext);
                            AST_STRING_FIELD(call_extension);
                            AST_STRING_FIELD(call_callerchan);
                            AST_STRING_FIELD(call_callerid););
  int call_priority;
  int has_tls;
};

enum audiosync_flags {
  MUXFLAG_APPEND = (1 << 1),
  MUXFLAG_BRIDGED = (1 << 2),
  MUXFLAG_VOLUME = (1 << 3),
  MUXFLAG_READVOLUME = (1 << 4),
  MUXFLAG_WRITEVOLUME = (1 << 5),
  MUXFLAG_COMBINED = (1 << 8),
  MUXFLAG_UID = (1 << 9),
  MUXFLAG_BEEP = (1 << 11),
  MUXFLAG_BEEP_START = (1 << 12),
  MUXFLAG_BEEP_STOP = (1 << 13),
  MUXFLAG_RWSYNC = (1 << 14),
  MUXFLAG_DIRECTION = (1 << 15),
  MUXFLAG_TLS = (1 << 16),
  MUXFLAG_RECONNECTION_TIMEOUT = (1 << 17),
  MUXFLAG_RECONNECTION_ATTEMPTS = (1 << 17),
};

enum audiosync_args {
  OPT_ARG_READVOLUME = 0,
  OPT_ARG_WRITEVOLUME,
  OPT_ARG_VOLUME,
  OPT_ARG_UID,
  OPT_ARG_BEEP_INTERVAL,
  OPT_ARG_RWSYNC,
  OPT_ARG_DIRECTION,
  OPT_ARG_TLS,
  OPT_ARG_RECONNECTION_TIMEOUT,
  OPT_ARG_RECONNECTION_ATTEMPTS,
  OPT_ARG_ARRAY_SIZE, /* Always last element of the enum */
};

AST_APP_OPTIONS(
    audiosync_opts,
    {
        AST_APP_OPTION('a', MUXFLAG_APPEND),
        AST_APP_OPTION('b', MUXFLAG_BRIDGED),
        AST_APP_OPTION_ARG('B', MUXFLAG_BEEP, OPT_ARG_BEEP_INTERVAL),
        AST_APP_OPTION('p', MUXFLAG_BEEP_START),
        AST_APP_OPTION('P', MUXFLAG_BEEP_STOP),
        AST_APP_OPTION_ARG('v', MUXFLAG_READVOLUME, OPT_ARG_READVOLUME),
        AST_APP_OPTION_ARG('V', MUXFLAG_WRITEVOLUME, OPT_ARG_WRITEVOLUME),
        AST_APP_OPTION_ARG('W', MUXFLAG_VOLUME, OPT_ARG_VOLUME),
        AST_APP_OPTION_ARG('i', MUXFLAG_UID, OPT_ARG_UID),
        AST_APP_OPTION_ARG('S', MUXFLAG_RWSYNC, OPT_ARG_RWSYNC),
        AST_APP_OPTION_ARG('D', MUXFLAG_DIRECTION, OPT_ARG_DIRECTION),
        AST_APP_OPTION_ARG('T', MUXFLAG_TLS, OPT_ARG_TLS),
        AST_APP_OPTION_ARG('R', MUXFLAG_RECONNECTION_TIMEOUT,
                           OPT_ARG_RECONNECTION_TIMEOUT),
        AST_APP_OPTION_ARG('r', MUXFLAG_RECONNECTION_ATTEMPTS,
                           OPT_ARG_RECONNECTION_ATTEMPTS),
    });

struct audiosync_ds {
  unsigned int destruction_ok;
  ast_cond_t destruction_condition;
  ast_mutex_t lock;
  /**
   * the audio hook we will use for sending raw audio
   */
  struct ast_audiohook *audiohook;

  unsigned int samp_rate;
  char *wsserver;
  char *beep_id;
  struct ast_tls_config *tls_cfg;
};

static void audiosync_ds_destroy(void *data) {
  struct audiosync_ds *audiosync_ds = data;

  ast_mutex_lock(&audiosync_ds->lock);
  audiosync_ds->audiohook = NULL;
  audiosync_ds->destruction_ok = 1;
  ast_free(audiosync_ds->wsserver);
  ast_free(audiosync_ds->beep_id);
  ast_cond_signal(&audiosync_ds->destruction_condition);
  ast_mutex_unlock(&audiosync_ds->lock);
}

static const struct ast_datastore_info audiosync_ds_info = {
    .type = "audiosync",
    .destroy = audiosync_ds_destroy,
};

static void destroy_monitor_audiohook(struct audiosync *audiosync) {
  if (audiosync->audiosync_ds) {
    ast_mutex_lock(&audiosync->audiosync_ds->lock);
    audiosync->audiosync_ds->audiohook = NULL;
    ast_mutex_unlock(&audiosync->audiosync_ds->lock);
  }
  /* kill the audiohook. */
  ast_audiohook_lock(&audiosync->audiohook);
  ast_audiohook_detach(&audiosync->audiohook);
  ast_audiohook_unlock(&audiosync->audiohook);
  ast_audiohook_destroy(&audiosync->audiohook);
}

static int start_audiosync(struct ast_channel *chan,
                           struct ast_audiohook *audiohook) {
  if (!chan) {
    return -1;
  }

  return ast_audiohook_attach(chan, audiohook);
}

static int audiosync_ws_close(struct audiosync *audiosync) {
  int ret;
  ast_verb(2, "[audiosync] Closing websocket connection\n");
  if (audiosync->websocket) {
    ast_verb(2, "[audiosync] Calling ast_websocket_close\n");
    ret = ast_websocket_close(audiosync->websocket, 1011);
    return ret;
  }

  ast_verb(2,
           "[audiosync] No reference to websocket, can't close connection\n");
  return -1;
}

/*
        1 = success
        0 = fail
*/
static enum ast_websocket_result
audiosync_ws_connect(struct audiosync *audiosync) {
  enum ast_websocket_result result;

  if (audiosync->websocket) {
    ast_verb(2,
             "<%s> [audiosync] (%s) Reconnecting to websocket server at: %s\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string, audiosync->audiosync_ds->wsserver);

    // close the websocket connection before reconnecting
    audiosync_ws_close(audiosync);

    ao2_cleanup(audiosync->websocket);
  } else {
    ast_verb(2, "<%s> [audiosync] (%s) Connecting to websocket server at: %s\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string, audiosync->audiosync_ds->wsserver);
  }

  // Check if we're running with TLS
  if (audiosync->has_tls == 1) {
    ast_verb(2,
             "<%s> [audiosync] (%s) Creating to WebSocket server with TLS mode "
             "enabled\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string);
    audiosync->websocket = ast_websocket_client_create(
        audiosync->audiosync_ds->wsserver, "echo", audiosync->tls_cfg, &result);
  } else {
    ast_verb(2,
             "<%s> [audiosync] (%s) Creating to WebSocket server without TLS\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string);
    audiosync->websocket = ast_websocket_client_create(
        audiosync->audiosync_ds->wsserver, "echo", NULL, &result);
  }

  return result;
}

/*
        reconn_status
        0 = OK
        1 = FAILED
*/
static int audiosync_start_reconnecting(struct audiosync *audiosync) {
  int counter = 0;
  int status = 0;
  int timeout = audiosync->reconnection_timeout;
  int attempts = audiosync->reconnection_attempts;
  int last_attempt = 0;
  int now;
  int delta;
  int result;

  while (counter < attempts) {
    now = (int)time(NULL);
    delta = now - last_attempt;

    // small check to see if we should keep waiting on the reconnection. This
    // uses the reconnection_timeout variable configured in the dialplan
    if (last_attempt != 0 && delta <= timeout) {
      // keep waiting
      continue;
    }

    // try to reconnect
    result = audiosync_ws_connect(audiosync);
    if (result == WS_OK) {
      status = 0;
      last_attempt = 0;
      break;
    }

    // reconnection failed...
    // update our counter with the last reconnection attempt
    last_attempt = (int)time(NULL);

    ast_log(
        LOG_ERROR,
        "<%s> [audiosync] (%s) Reconnection failed... trying again in %d "
        "seconds. %d attempts remaining reconn_now %d reconn_last_attempt %d\n",
        ast_channel_name(audiosync->autochan->chan),
        audiosync->direction_string, timeout, (attempts - counter), now,
        last_attempt);

    counter++;
    status = 1;
  }

  return status;
}

static void audiosync_free(struct audiosync *audiosync) {
  if (audiosync) {
    if (audiosync->audiosync_ds) {
      ast_mutex_destroy(&audiosync->audiosync_ds->lock);
      ast_cond_destroy(&audiosync->audiosync_ds->destruction_condition);
      ast_free(audiosync->audiosync_ds);
    }

    ast_free(audiosync->name);
    ast_free(audiosync->post_process);
    ast_free(audiosync->wsserver);

    audiosync_ws_close(audiosync);

    /* clean stringfields */
    ast_string_field_free_memory(audiosync);

    ast_free(audiosync);
  }
}

static void *audiosync_thread(void *obj) {
  struct audiosync *audiosync = obj;
  struct ast_format *format_slin;
  char *channel_name_cleanup;
  enum ast_websocket_result result;
  int frames_sent = 0;
  int reconn_status;

  /* Keep callid association before any log messages */
  if (audiosync->callid) {
    ast_verb(2, "<%s> [audiosync] (%s) Keeping Call-ID Association\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string);
    ast_callid_threadassoc_add(audiosync->callid);
  }

  result = audiosync_ws_connect(audiosync);
  if (result != WS_OK) {
    ast_log(LOG_ERROR, "<%s> Could not connect to websocket server: %s\n",
            ast_channel_name(audiosync->autochan->chan),
            audiosync->audiosync_ds->wsserver);

    ast_test_suite_event_notify("audiosync_END", "Ws server: %s\r\n",
                                audiosync->wsserver);

    /* kill the audiohook */
    destroy_monitor_audiohook(audiosync);
    ast_autochan_destroy(audiosync->autochan);

    /* We specifically don't do audiosync_free(audiosync) here because the
     * automatic datastore cleanup will get it */

    ast_module_unref(ast_module_info->self);

    return 0;
  }

  ast_verb(2, "<%s> [audiosync] (%s) Begin audiosync Recording %s\n",
           ast_channel_name(audiosync->autochan->chan),
           audiosync->direction_string, audiosync->name);

  // fs = &audiosync->audiosync_ds->fs;

  ast_mutex_lock(&audiosync->audiosync_ds->lock);
  format_slin =
      ast_format_cache_get_slin_by_rate(audiosync->audiosync_ds->samp_rate);

  ast_mutex_unlock(&audiosync->audiosync_ds->lock);

  /* The audiohook must enter and exit the loop locked */
  ast_audiohook_lock(&audiosync->audiohook);

  while (audiosync->audiohook.status == AST_AUDIOHOOK_STATUS_RUNNING) {
    // ast_verb(2, "<%s> [audiosync] (%s) Reading Audio Hook frame...\n",
    // ast_channel_name(audiosync->autochan->chan),
    // audiosync->direction_string);
    struct ast_frame *fr =
        ast_audiohook_read_frame(&audiosync->audiohook, SAMPLES_PER_FRAME,
                                 audiosync->direction, format_slin);

    if (!fr) {
      ast_audiohook_trigger_wait(&audiosync->audiohook);

      if (audiosync->audiohook.status != AST_AUDIOHOOK_STATUS_RUNNING) {
        ast_verb(2, "<%s> [audiosync] (%s) AST_AUDIOHOOK_STATUS_RUNNING = 0\n",
                 ast_channel_name(audiosync->autochan->chan),
                 audiosync->direction_string);
        break;
      }

      continue;
    }

    /* audiohook lock is not required for the next block.
     * Unlock it, but remember to lock it before looping or exiting */
    ast_audiohook_unlock(&audiosync->audiohook);
    struct ast_frame *cur;

    // ast_mutex_lock(&audiosync->audiosync_ds->lock);
    for (cur = fr; cur; cur = AST_LIST_NEXT(cur, frame_list)) {
      // ast_verb(2, "<%s> sending audio frame to websocket...\n",
      // ast_channel_name(audiosync->autochan->chan));
      // ast_mutex_lock(&audiosync->audiosync_ds->lock);

      if (ast_websocket_write(audiosync->websocket, AST_WEBSOCKET_OPCODE_BINARY,
                              cur->data.ptr, cur->datalen)) {

        ast_log(LOG_ERROR,
                "<%s> [audiosync] (%s) Could not write to websocket.  "
                "Reconnecting...\n",
                ast_channel_name(audiosync->autochan->chan),
                audiosync->direction_string);
        reconn_status = audiosync_start_reconnecting(audiosync);

        if (reconn_status == 1) {
          audiosync->websocket = NULL;
          audiosync->audiohook.status = AST_AUDIOHOOK_STATUS_SHUTDOWN;
          break;
        }

        /* re-send the last frame */
        if (ast_websocket_write(audiosync->websocket,
                                AST_WEBSOCKET_OPCODE_BINARY, cur->data.ptr,
                                cur->datalen)) {
          ast_log(LOG_ERROR,
                  "<%s> [audiosync] (%s) Could not re-write to websocket.  "
                  "Complete Failure.\n",
                  ast_channel_name(audiosync->autochan->chan),
                  audiosync->direction_string);

          audiosync->audiohook.status = AST_AUDIOHOOK_STATUS_SHUTDOWN;
          break;
        }
      }

      frames_sent++;
    }

    // ast_mutex_unlock(&audiosync->audiosync_ds->lock);
    //

    /* All done! free it. */
    if (fr) {
      ast_frame_free(fr, 0);
    }

    fr = NULL;

    ast_audiohook_lock(&audiosync->audiohook);
  }

  ast_audiohook_unlock(&audiosync->audiohook);

  if (ast_test_flag(audiosync, MUXFLAG_BEEP_STOP)) {
    ast_autochan_channel_lock(audiosync->autochan);
    ast_stream_and_wait(audiosync->autochan->chan, "beep", "");
    ast_autochan_channel_unlock(audiosync->autochan);
  }

  channel_name_cleanup =
      ast_strdupa(ast_channel_name(audiosync->autochan->chan));

  ast_autochan_destroy(audiosync->autochan);

  /* Datastore cleanup.  close the filestream and wait for ds destruction */
  ast_mutex_lock(&audiosync->audiosync_ds->lock);
  if (!audiosync->audiosync_ds->destruction_ok) {
    ast_cond_wait(&audiosync->audiosync_ds->destruction_condition,
                  &audiosync->audiosync_ds->lock);
  }
  ast_mutex_unlock(&audiosync->audiosync_ds->lock);

  /* kill the audiohook */
  destroy_monitor_audiohook(audiosync);

  ast_verb(
      2,
      "<%s> [audiosync] (%s) Finished processing audiohook. Frames sent = %d\n",
      channel_name_cleanup, audiosync->direction_string, frames_sent);
  ast_verb(2, "<%s> [audiosync] (%s) Post Process\n", channel_name_cleanup,
           audiosync->direction_string);

  if (audiosync->post_process) {
    ast_verb(2, "<%s> [audiosync] (%s) Executing [%s]\n", channel_name_cleanup,
             audiosync->direction_string, audiosync->post_process);
    ast_safe_system(audiosync->post_process);
  }

  // audiosync->name

  ast_verb(2, "<%s> [audiosync] (%s) End audiosync Recording to: %s\n",
           channel_name_cleanup, audiosync->direction_string,
           audiosync->wsserver);
  ast_test_suite_event_notify("audiosync_END", "Ws server: %s\r\n",
                              audiosync->wsserver);

  /* free any audiosync memory */
  audiosync_free(audiosync);

  ast_module_unref(ast_module_info->self);

  return NULL;
}

static int setup_audiosync_ds(struct audiosync *audiosync,
                              struct ast_channel *chan, char **datastore_id,
                              const char *beep_id) {
  struct ast_datastore *datastore = NULL;
  struct audiosync_ds *audiosync_ds;

  if (!(audiosync_ds = ast_calloc(1, sizeof(*audiosync_ds)))) {
    return -1;
  }

  if (ast_asprintf(datastore_id, "%p", audiosync_ds) == -1) {
    ast_log(LOG_ERROR, "Failed to allocate memory for audiosync ID.\n");
    ast_free(audiosync_ds);
    return -1;
  }

  ast_mutex_init(&audiosync_ds->lock);
  ast_cond_init(&audiosync_ds->destruction_condition, NULL);

  if (!(datastore = ast_datastore_alloc(&audiosync_ds_info, *datastore_id))) {
    ast_mutex_destroy(&audiosync_ds->lock);
    ast_cond_destroy(&audiosync_ds->destruction_condition);
    ast_free(audiosync_ds);
    return -1;
  }

  if (ast_test_flag(audiosync, MUXFLAG_BEEP_START)) {
    ast_autochan_channel_lock(audiosync->autochan);
    ast_stream_and_wait(audiosync->autochan->chan, "beep", "");
    ast_autochan_channel_unlock(audiosync->autochan);
  }

  audiosync_ds->samp_rate = 8000;
  audiosync_ds->audiohook = &audiosync->audiohook;
  audiosync_ds->wsserver = ast_strdup(audiosync->wsserver);
  if (!ast_strlen_zero(beep_id)) {
    audiosync_ds->beep_id = ast_strdup(beep_id);
  }
  datastore->data = audiosync_ds;

  ast_channel_lock(chan);
  ast_channel_datastore_add(chan, datastore);
  ast_channel_unlock(chan);

  audiosync->audiosync_ds = audiosync_ds;
  return 0;
}

static int launch_audiosync_thread(
    struct ast_channel *chan, const char *wsserver, unsigned int flags,
    enum ast_audiohook_direction direction, char *tcert, int reconn_timeout,
    int reconn_attempts, int readvol, int writevol, const char *post_process,
    const char *uid_channel_var, const char *beep_id) {
  pthread_t thread;
  struct audiosync *audiosync;
  char postprocess2[1024] = "";
  char *datastore_id = NULL;

  postprocess2[0] = 0;
  /* If a post process system command is given attach it to the structure */
  if (!ast_strlen_zero(post_process)) {
    char *p1, *p2;

    p1 = ast_strdupa(post_process);
    for (p2 = p1; *p2; p2++) {
      if (*p2 == '^' && *(p2 + 1) == '{') {
        *p2 = '$';
      }
    }
    ast_channel_lock(chan);
    pbx_substitute_variables_helper(chan, p1, postprocess2,
                                    sizeof(postprocess2) - 1);
    ast_channel_unlock(chan);
  }

  /* Pre-allocate audiosync structure and spy */
  if (!(audiosync = ast_calloc(1, sizeof(*audiosync)))) {
    return -1;
  }

  /* Now that the struct has been calloced, go ahead and initialize the string
   * fields. */
  if (ast_string_field_init(audiosync, 512)) {
    audiosync_free(audiosync);
    return -1;
  }

  /* Setup the actual spy before creating our thread */
  if (ast_audiohook_init(&audiosync->audiohook, AST_AUDIOHOOK_TYPE_SPY,
                         audiosync_spy_type, 0)) {
    audiosync_free(audiosync);
    return -1;
  }

  /* Copy over flags and channel name */
  audiosync->flags = flags;
  if (!(audiosync->autochan = ast_autochan_setup(chan))) {
    audiosync_free(audiosync);
    return -1;
  }

  /* Direction */
  audiosync->direction = direction;

  if (direction == AST_AUDIOHOOK_DIRECTION_READ) {
    audiosync->direction_string = "in";
  } else if (direction == AST_AUDIOHOOK_DIRECTION_WRITE) {
    audiosync->direction_string = "out";
  } else {
    audiosync->direction_string = "both";
  }

  ast_verb(2, "<%s> [audiosync] (%s) Setting Direction\n",
           ast_channel_name(chan), audiosync->direction_string);

  // TODO: make this configurable
  audiosync->reconnection_attempts = reconn_attempts;
  // 5 seconds
  audiosync->reconnection_timeout = reconn_timeout;

  ast_verb(2, "<%s> [audiosync] Setting reconnection attempts to %d\n",
           ast_channel_name(chan), audiosync->reconnection_attempts);
  ast_verb(2, "<%s> [audiosync] Setting reconnection timeout to %d\n",
           ast_channel_name(chan), audiosync->reconnection_timeout);

  /* Server */
  if (!ast_strlen_zero(wsserver)) {
    ast_verb(2, "<%s> [audiosync] (%s) Setting wsserver: %s\n",
             ast_channel_name(chan), audiosync->direction_string, wsserver);
    audiosync->wsserver = ast_strdup(wsserver);
  }

  /* TLS */
  audiosync->has_tls = 0;
  if (!ast_strlen_zero(tcert)) {
    ast_verb(2, "<%s> [audiosync] (%s) Setting TLS Cert: %s\n",
             ast_channel_name(chan), audiosync->direction_string, tcert);
    struct ast_tls_config *ast_tls_config;
    audiosync->tls_cfg = ast_calloc(1, sizeof(*ast_tls_config));
    audiosync->has_tls = 1;
    ast_set_flag(&audiosync->tls_cfg->flags, AST_SSL_DONT_VERIFY_SERVER);
  }

  if (setup_audiosync_ds(audiosync, chan, &datastore_id, beep_id)) {
    ast_autochan_destroy(audiosync->autochan);
    audiosync_free(audiosync);
    ast_free(datastore_id);
    return -1;
  }

  ast_verb(2, "<%s> [audiosync] (%s) Completed Setup\n",
           ast_channel_name(audiosync->autochan->chan),
           audiosync->direction_string);
  if (!ast_strlen_zero(uid_channel_var)) {
    if (datastore_id) {
      pbx_builtin_setvar_helper(chan, uid_channel_var, datastore_id);
    }
  }

  ast_free(datastore_id);
  audiosync->name = ast_strdup(ast_channel_name(chan));

  if (!ast_strlen_zero(postprocess2)) {
    audiosync->post_process = ast_strdup(postprocess2);
  }

  ast_set_flag(&audiosync->audiohook, AST_AUDIOHOOK_TRIGGER_SYNC);
  if ((ast_test_flag(audiosync, MUXFLAG_RWSYNC))) {
    ast_set_flag(&audiosync->audiohook, AST_AUDIOHOOK_SUBSTITUTE_SILENCE);
  }

  if (readvol)
    audiosync->audiohook.options.read_volume = readvol;
  if (writevol)
    audiosync->audiohook.options.write_volume = writevol;

  if (start_audiosync(chan, &audiosync->audiohook)) {
    ast_log(LOG_WARNING, "<%s> (%s) [audiosync] Unable to add spy type '%s'\n",
            audiosync->direction_string, ast_channel_name(chan),
            audiosync_spy_type);
    ast_audiohook_destroy(&audiosync->audiohook);
    audiosync_free(audiosync);
    return -1;
  }

  ast_verb(2, "<%s> [audiosync] (%s) Added AudioHook Spy\n",
           ast_channel_name(chan), audiosync->direction_string);

  /* reference be released at audiosync destruction */
  audiosync->callid = ast_read_threadstorage_callid();

  return ast_pthread_create_detached_background(&thread, NULL, audiosync_thread,
                                                audiosync);
}

static int audiosync_exec(struct ast_channel *chan, const char *data) {
  int x, readvol = 0, writevol = 0;
  char *uid_channel_var = NULL;
  char beep_id[64] = "";
  unsigned int direction = 2;

  struct ast_flags flags = {0};
  char *parse;
  char *tcert = NULL;
  int reconn_timeout = 5;
  int reconn_attempts = 5;
  AST_DECLARE_APP_ARGS(args, AST_APP_ARG(wsserver); AST_APP_ARG(options);
                       AST_APP_ARG(post_process););

  ast_log(LOG_NOTICE, "audiosync created with args %s\n", data);
  if (ast_strlen_zero(data)) {
    ast_log(LOG_WARNING, "audiosync requires an argument wsserver\n");
    return -1;
  }

  parse = ast_strdupa(data);

  AST_STANDARD_APP_ARGS(args, parse);

  if (args.options) {
    char *opts[OPT_ARG_ARRAY_SIZE] = {
        NULL,
    };

    ast_app_parse_options(audiosync_opts, &flags, opts, args.options);

    if (ast_test_flag(&flags, MUXFLAG_READVOLUME)) {
      if (ast_strlen_zero(opts[OPT_ARG_READVOLUME])) {
        ast_log(LOG_WARNING, "No volume level was provided for the heard "
                             "volume ('v') option.\n");
      } else if ((sscanf(opts[OPT_ARG_READVOLUME], "%2d", &x) != 1) ||
                 (x < -4) || (x > 4)) {
        ast_log(LOG_NOTICE,
                "Heard volume must be a number between -4 and 4, not '%s'\n",
                opts[OPT_ARG_READVOLUME]);
      } else {
        readvol = get_volfactor(x);
      }
    }

    if (ast_test_flag(&flags, MUXFLAG_WRITEVOLUME)) {
      if (ast_strlen_zero(opts[OPT_ARG_WRITEVOLUME])) {
        ast_log(LOG_WARNING, "No volume level was provided for the spoken "
                             "volume ('V') option.\n");
      } else if ((sscanf(opts[OPT_ARG_WRITEVOLUME], "%2d", &x) != 1) ||
                 (x < -4) || (x > 4)) {
        ast_log(LOG_NOTICE,
                "Spoken volume must be a number between -4 and 4, not '%s'\n",
                opts[OPT_ARG_WRITEVOLUME]);
      } else {
        writevol = get_volfactor(x);
      }
    }

    if (ast_test_flag(&flags, MUXFLAG_VOLUME)) {
      if (ast_strlen_zero(opts[OPT_ARG_VOLUME])) {
        ast_log(LOG_WARNING, "No volume level was provided for the combined "
                             "volume ('W') option.\n");
      } else if ((sscanf(opts[OPT_ARG_VOLUME], "%2d", &x) != 1) || (x < -4) ||
                 (x > 4)) {
        ast_log(LOG_NOTICE,
                "Combined volume must be a number between -4 and 4, not '%s'\n",
                opts[OPT_ARG_VOLUME]);
      } else {
        readvol = writevol = get_volfactor(x);
      }
    }

    if (ast_test_flag(&flags, MUXFLAG_UID)) {
      uid_channel_var = opts[OPT_ARG_UID];
    }

    if (ast_test_flag(&flags, MUXFLAG_BEEP)) {
      const char *interval_str = S_OR(opts[OPT_ARG_BEEP_INTERVAL], "15");
      unsigned int interval = 15;

      if (sscanf(interval_str, "%30u", &interval) != 1) {
        ast_log(
            LOG_WARNING,
            "Invalid interval '%s' for periodic beep. Using default of %u\n",
            interval_str, interval);
      }

      if (ast_beep_start(chan, interval, beep_id, sizeof(beep_id))) {
        ast_log(LOG_WARNING, "Unable to enable periodic beep, please ensure "
                             "func_periodic_hook is loaded.\n");
        return -1;
      }
    }
    if (ast_test_flag(&flags, MUXFLAG_DIRECTION)) {
      const char *direction_str = opts[OPT_ARG_DIRECTION];

      if (!strcmp(direction_str, "in")) {
        direction = AST_AUDIOHOOK_DIRECTION_READ;
      } else if (!strcmp(direction_str, "out")) {
        direction = AST_AUDIOHOOK_DIRECTION_WRITE;
      } else if (!strcmp(direction_str, "both")) {
        direction = AST_AUDIOHOOK_DIRECTION_BOTH;
      } else {
        direction = AST_AUDIOHOOK_DIRECTION_BOTH;

        ast_log(LOG_WARNING,
                "Invalid direction '%s' given. Using default of 'both'\n",
                opts[OPT_ARG_DIRECTION]);
      }
    }

    if (ast_test_flag(&flags, MUXFLAG_TLS)) {
      tcert = ast_strdup(S_OR(opts[OPT_ARG_TLS], ""));
      ast_verb(2, "Parsing TLS result tcert: %s\n", tcert);
    }

    if (ast_test_flag(&flags, MUXFLAG_RECONNECTION_TIMEOUT)) {
      reconn_timeout = atoi(S_OR(opts[OPT_ARG_RECONNECTION_TIMEOUT], "15"));
      ast_verb(2, "Reconnection timeout set to: %d\n", reconn_timeout);
    }

    if (ast_test_flag(&flags, MUXFLAG_RECONNECTION_ATTEMPTS)) {
      reconn_attempts = atoi(S_OR(opts[OPT_ARG_RECONNECTION_ATTEMPTS], "15"));
      ast_verb(2, "Reconnection attempts set to: %d\n", reconn_attempts);
    }
  }

  /* If there are no file writing arguments/options for the mix monitor, send a
   * warning message and return -1 */

  if (ast_strlen_zero(args.wsserver)) {
    ast_log(LOG_WARNING, "audiosync requires an argument (wsserver)\n");
    return -1;
  }

  pbx_builtin_setvar_helper(chan, "audiosync_WSSERVER", args.wsserver);

  /* If launch_monitor_thread works, the module reference must not be released
   * until it is finished. */
  ast_module_ref(ast_module_info->self);

  if (launch_audiosync_thread(chan, args.wsserver, flags.flags, direction,
                              tcert, reconn_timeout, reconn_attempts, readvol,
                              writevol, args.post_process, uid_channel_var,
                              beep_id)) {

    /* Failed */
    ast_module_unref(ast_module_info->self);
  }

  return 0;
}

static int stop_audiosync_full(struct ast_channel *chan, const char *data) {
  struct ast_datastore *datastore = NULL;
  char *parse = "";
  struct audiosync_ds *audiosync_ds;
  const char *beep_id = NULL;

  AST_DECLARE_APP_ARGS(args, AST_APP_ARG(audiosyncid););

  if (!ast_strlen_zero(data)) {
    parse = ast_strdupa(data);
  }

  AST_STANDARD_APP_ARGS(args, parse);

  ast_channel_lock(chan);

  datastore = ast_channel_datastore_find(chan, &audiosync_ds_info,
                                         S_OR(args.audiosyncid, NULL));
  if (!datastore) {
    ast_channel_unlock(chan);
    return -1;
  }
  audiosync_ds = datastore->data;

  ast_mutex_lock(&audiosync_ds->lock);

  /* The audiosync thread may be waiting on the audiohook trigger.
   * In order to exit from the audiosync loop before waiting on channel
   * destruction, poke the audiohook trigger. */
  if (audiosync_ds->audiohook) {
    if (audiosync_ds->audiohook->status != AST_AUDIOHOOK_STATUS_DONE) {
      ast_audiohook_update_status(audiosync_ds->audiohook,
                                  AST_AUDIOHOOK_STATUS_SHUTDOWN);
    }
    ast_audiohook_lock(audiosync_ds->audiohook);
    ast_cond_signal(&audiosync_ds->audiohook->trigger);
    ast_audiohook_unlock(audiosync_ds->audiohook);
    audiosync_ds->audiohook = NULL;
  }

  if (!ast_strlen_zero(audiosync_ds->beep_id)) {
    beep_id = ast_strdupa(audiosync_ds->beep_id);
  }

  ast_mutex_unlock(&audiosync_ds->lock);

  /* Remove the datastore so the monitor thread can exit */
  if (!ast_channel_datastore_remove(chan, datastore)) {
    ast_datastore_free(datastore);
  }

  ast_channel_unlock(chan);

  if (!ast_strlen_zero(beep_id)) {
    ast_beep_stop(chan, beep_id);
  }

  return 0;
}

static int stop_audiosync_exec(struct ast_channel *chan, const char *data) {
  stop_audiosync_full(chan, data);
  return 0;
}

static char *handle_cli_audiosync(struct ast_cli_entry *e, int cmd,
                                  struct ast_cli_args *a) {
  struct ast_channel *chan;
  struct ast_datastore *datastore = NULL;
  struct audiosync_ds *audiosync_ds = NULL;

  switch (cmd) {
  case CLI_INIT:
    e->command = "audiosync {start|stop|list}";
    e->usage = "Usage: audiosync start <chan_name> [args]\n"
               "         The optional arguments are passed to the audiosync "
               "application.\n"
               "       audiosync stop <chan_name> [args]\n"
               "         The optional arguments are passed to the "
               "Stopaudiosync application.\n"
               "       audiosync list <chan_name>\n";
    return NULL;
  case CLI_GENERATE:
    return ast_complete_channels(a->line, a->word, a->pos, a->n, 2);
  }

  if (a->argc < 3) {
    return CLI_SHOWUSAGE;
  }

  if (!(chan =
            ast_channel_get_by_name_prefix(a->argv[2], strlen(a->argv[2])))) {
    ast_cli(a->fd, "No channel matching '%s' found.\n", a->argv[2]);
    /* Technically this is a failure, but we don't want 2 errors printing out */
    return CLI_SUCCESS;
  }

  if (!strcasecmp(a->argv[1], "start")) {
    audiosync_exec(chan, (a->argc >= 4) ? a->argv[3] : "");
  } else if (!strcasecmp(a->argv[1], "stop")) {
    stop_audiosync_exec(chan, (a->argc >= 4) ? a->argv[3] : "");
  } else if (!strcasecmp(a->argv[1], "list")) {
    ast_cli(a->fd, "audiosync ID\tWs Server\tReceive File\tTransmit File\n");
    ast_cli(a->fd, "==========================================================="
                   "==============\n");
    ast_channel_lock(chan);
    AST_LIST_TRAVERSE(ast_channel_datastores(chan), datastore, entry) {
      if (datastore->info == &audiosync_ds_info) {
        char *wsserver = "";
        char *filename_read = "";
        char *filename_write = "";

        audiosync_ds = datastore->data;
        if (audiosync_ds->wsserver) {
          wsserver = audiosync_ds->wsserver;
        }
        ast_cli(a->fd, "%p\t%s\t%s\t%s\n", audiosync_ds, wsserver,
                filename_read, filename_write);
      }
    }
    ast_channel_unlock(chan);
  } else {
    chan = ast_channel_unref(chan);
    return CLI_SHOWUSAGE;
  }

  chan = ast_channel_unref(chan);

  return CLI_SUCCESS;
}

/*! \brief  Mute / unmute  a MixMonitor channel */
static int manager_mute_audiosync(struct mansession *s,
                                  const struct message *m) {
  struct ast_channel *c;
  const char *name = astman_get_header(m, "Channel");
  const char *id = astman_get_header(m, "ActionID");
  const char *state = astman_get_header(m, "State");
  const char *direction = astman_get_header(m, "Direction");
  int clearmute = 1;
  enum ast_audiohook_flags flag;

  if (ast_strlen_zero(direction)) {
    astman_send_error(s, m,
                      "No direction specified. Must be read, write or both");
    return AMI_SUCCESS;
  }

  if (!strcasecmp(direction, "read")) {
    flag = AST_AUDIOHOOK_MUTE_READ;
  } else if (!strcasecmp(direction, "write")) {
    flag = AST_AUDIOHOOK_MUTE_WRITE;
  } else if (!strcasecmp(direction, "both")) {
    flag = AST_AUDIOHOOK_MUTE_READ | AST_AUDIOHOOK_MUTE_WRITE;
  } else {
    astman_send_error(
        s, m, "Invalid direction specified. Must be read, write or both");
    return AMI_SUCCESS;
  }

  if (ast_strlen_zero(name)) {
    astman_send_error(s, m, "No channel specified");
    return AMI_SUCCESS;
  }

  if (ast_strlen_zero(state)) {
    astman_send_error(s, m, "No state specified");
    return AMI_SUCCESS;
  }

  clearmute = ast_false(state);

  c = ast_channel_get_by_name(name);
  if (!c) {
    astman_send_error(s, m, "No such channel");
    return AMI_SUCCESS;
  }

  if (ast_audiohook_set_mute(c, audiosync_spy_type, flag, clearmute)) {
    ast_channel_unref(c);
    astman_send_error(s, m, "Cannot set mute flag");
    return AMI_SUCCESS;
  }

  astman_append(s, "Response: Success\r\n");

  if (!ast_strlen_zero(id)) {
    astman_append(s, "ActionID: %s\r\n", id);
  }

  astman_append(s, "\r\n");

  ast_channel_unref(c);

  return AMI_SUCCESS;
}

static int manager_audiosync(struct mansession *s, const struct message *m) {
  struct ast_channel *c;
  const char *name = astman_get_header(m, "Channel");
  const char *id = astman_get_header(m, "ActionID");
  const char *wsserver = astman_get_header(m, "WsServer");
  const char *options = astman_get_header(m, "Options");
  // const char *command = astman_get_header(m, "Command");
  char *opts[OPT_ARG_ARRAY_SIZE] = {
      NULL,
  };
  struct ast_flags flags = {0};
  char *uid_channel_var = NULL;
  const char *audiosync_id = NULL;
  int res;
  char args[PATH_MAX];

  if (ast_strlen_zero(name)) {
    astman_send_error(s, m, "No channel specified");
    return AMI_SUCCESS;
  }

  c = ast_channel_get_by_name(name);
  if (!c) {
    astman_send_error(s, m, "No such channel");
    return AMI_SUCCESS;
  }

  if (!ast_strlen_zero(options)) {
    ast_app_parse_options(audiosync_opts, &flags, opts, ast_strdupa(options));
  }

  snprintf(args, sizeof(args), "%s,%s", wsserver, options);

  res = audiosync_exec(c, args);

  if (ast_test_flag(&flags, MUXFLAG_UID)) {
    uid_channel_var = opts[OPT_ARG_UID];
    ast_channel_lock(c);
    audiosync_id = pbx_builtin_getvar_helper(c, uid_channel_var);
    audiosync_id = ast_strdupa(S_OR(audiosync_id, ""));
    ast_channel_unlock(c);
  }

  if (res) {
    ast_channel_unref(c);
    astman_send_error(s, m, "Could not start monitoring channel");
    return AMI_SUCCESS;
  }

  astman_append(s, "Response: Success\r\n");

  if (!ast_strlen_zero(id)) {
    astman_append(s, "ActionID: %s\r\n", id);
  }

  if (!ast_strlen_zero(audiosync_id)) {
    astman_append(s, "audiosyncID: %s\r\n", audiosync_id);
  }

  astman_append(s, "\r\n");

  ast_channel_unref(c);

  return AMI_SUCCESS;
}

static int manager_stop_audiosync(struct mansession *s,
                                  const struct message *m) {
  struct ast_channel *c;
  const char *name = astman_get_header(m, "Channel");
  const char *id = astman_get_header(m, "ActionID");
  const char *audiosync_id = astman_get_header(m, "audiosyncID");
  int res;

  if (ast_strlen_zero(name)) {
    astman_send_error(s, m, "No channel specified");
    return AMI_SUCCESS;
  }

  c = ast_channel_get_by_name(name);
  if (!c) {
    astman_send_error(s, m, "No such channel");
    return AMI_SUCCESS;
  }

  res = stop_audiosync_full(c, audiosync_id);
  if (res) {
    ast_channel_unref(c);
    astman_send_error(s, m, "Could not stop monitoring channel");
    return AMI_SUCCESS;
  }

  astman_append(s, "Response: Success\r\n");

  if (!ast_strlen_zero(id)) {
    astman_append(s, "ActionID: %s\r\n", id);
  }

  astman_append(s, "\r\n");

  ast_channel_unref(c);

  return AMI_SUCCESS;
}

static int func_audiosync_read(struct ast_channel *chan, const char *cmd,
                               char *data, char *buf, size_t len) {
  struct ast_datastore *datastore;
  struct audiosync_ds *ds_data;
  AST_DECLARE_APP_ARGS(args, AST_APP_ARG(id); AST_APP_ARG(key););

  AST_STANDARD_APP_ARGS(args, data);

  if (ast_strlen_zero(args.id) || ast_strlen_zero(args.key)) {
    ast_log(
        LOG_WARNING,
        "Not enough arguments provided to %s. An ID and key must be provided\n",
        cmd);
    return -1;
  }

  ast_channel_lock(chan);
  datastore = ast_channel_datastore_find(chan, &audiosync_ds_info, args.id);
  ast_channel_unlock(chan);

  if (!datastore) {
    ast_log(LOG_WARNING, "Could not find audiosync with ID %s\n", args.id);
    return -1;
  }

  ds_data = datastore->data;

  if (!strcasecmp(args.key, "filename")) {
    ast_copy_string(buf, ds_data->wsserver, len);
  } else {
    ast_log(LOG_WARNING, "Unrecognized %s option %s\n", cmd, args.key);
    return -1;
  }
  return 0;
}

static struct ast_custom_function audiosync_function = {
    .name = "audiosync",
    .read = func_audiosync_read,
};

static struct ast_cli_entry cli_audiosync[] = {
    AST_CLI_DEFINE(handle_cli_audiosync, "Execute a audiosync command")};

static int set_audiosync_methods(void) { return 0; }

static int clear_audiosync_methods(void) { return 0; }

static int unload_module(void) {
  int res;

  ast_cli_unregister_multiple(cli_audiosync, ARRAY_LEN(cli_audiosync));
  res = ast_unregister_application(stop_app);
  res |= ast_unregister_application(app);
  res |= ast_manager_unregister("audiosyncMute");
  res |= ast_manager_unregister("audiosync");
  res |= ast_manager_unregister("Stopaudiosync");
  res |= ast_custom_function_unregister(&audiosync_function);
  res |= clear_audiosync_methods();

  return res;
}

static int load_module(void) {
  int res;

  ast_cli_register_multiple(cli_audiosync, ARRAY_LEN(cli_audiosync));
  res = ast_register_application_xml(app, audiosync_exec);
  res |= ast_register_application_xml(stop_app, stop_audiosync_exec);
  res |= ast_manager_register_xml("audiosyncMute",
                                  EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL,
                                  manager_mute_audiosync);
  res |= ast_manager_register_xml("audiosync", EVENT_FLAG_SYSTEM,
                                  manager_audiosync);
  res |= ast_manager_register_xml("Stopaudiosync",
                                  EVENT_FLAG_SYSTEM | EVENT_FLAG_CALL,
                                  manager_stop_audiosync);
  res |= ast_custom_function_register(&audiosync_function);
  res |= set_audiosync_methods();

  return res;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
                "Audio Forking application",
                .support_level = AST_MODULE_SUPPORT_CORE, .load = load_module,
                .unload = unload_module,
                .optional_modules = "func_periodic_hook", );
