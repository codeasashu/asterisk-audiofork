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

#define AUD_SYNC_INITIAL_FILE_SIZE 4096 // 64 kb block

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
  char *filename;
  int audio_fd; // audio fd
  void *audio_mmap; // audio mmap
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
};

enum audiosync_flags {
  MUXFLAG_DIRECTION = (1 << 15),
};

enum audiosync_args {
  OPT_ARG_DIRECTION,
  OPT_ARG_ARRAY_SIZE, /* Always last element of the enum */
};

AST_APP_OPTIONS(audiosync_opts, {
                                    AST_APP_OPTION_ARG('D', MUXFLAG_DIRECTION,
                                                       OPT_ARG_DIRECTION),
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
  char *filename;
  char *beep_id;
};

static void audiosync_ds_destroy(void *data) {
  struct audiosync_ds *audiosync_ds = data;

  ast_mutex_lock(&audiosync_ds->lock);
  audiosync_ds->audiohook = NULL;
  audiosync_ds->destruction_ok = 1;
  ast_free(audiosync_ds->filename);
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

static int audiosync_fs_close(struct audiosync *audiosync) {
  ast_verb(2, "[audiosync] Closing sync\n");
  close(audiosync->audio_fd);
  // fsync(audiosync->audio_fd); // @TODO: current this doesn't anything. Mayube we need in future
  return 0;
}

static void audiosync_free(struct audiosync *audiosync) {
  if (audiosync) {
    if (audiosync->audiosync_ds) {
      ast_mutex_destroy(&audiosync->audiosync_ds->lock);
      ast_cond_destroy(&audiosync->audiosync_ds->destruction_condition);
      ast_free(audiosync->audiosync_ds);
    }

    ast_free(audiosync->name);
    ast_free(audiosync->filename);

    audiosync_fs_close(audiosync);

    /* clean stringfields */
    ast_string_field_free_memory(audiosync);

    ast_free(audiosync);
  }
}

/*
        1 = success
        0 = fail
*/
int audiosync_fs_connect(struct audiosync *audiosync) {
  int fd;
  ast_verb(2, "<%s> [audiosync] (%s) Opening recording file %s \n",
           ast_channel_name(audiosync->autochan->chan),
           audiosync->direction_string,
	   audiosync->filename);
  //fd = open(audiosync->filename, O_RDWR | O_CREAT | O_APPEND, 0666);
  fd = open(audiosync->filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if(fd < 0) {
    ast_log(LOG_ERROR, "Unable to open recording file %s : %s\n", audiosync->filename, strerror(errno));
    ast_autochan_destroy(audiosync->autochan);
    audiosync_free(audiosync);
    return -1;
  }
  audiosync->audio_fd = fd;
  if (audiosync->audio_fd == -1) {
    ast_log(LOG_ERROR,
            "<%s> [audiosync] (%s) Failed to open recording file to write\n",
            ast_channel_name(audiosync->autochan->chan),
            audiosync->direction_string);
    ast_autochan_destroy(audiosync->autochan);
    audiosync_free(audiosync);
    return -1;
  } else {
    ast_verb(2, "<%s> [audiosync] (%s) opened recording file to write: %s\n",
            ast_channel_name(audiosync->autochan->chan),
            audiosync->direction_string, audiosync->filename);
  }
  return 0;
}

static void *audiosync_thread(void *obj) {
  struct audiosync *audiosync = obj;
  struct ast_format *format_slin;
  char *channel_name_cleanup;
  int result;
  int frames_sent = 0;

  /* Keep callid association before any log messages */
  if (audiosync->callid) {
    ast_verb(2, "<%s> [audiosync] (%s) Keeping Call-ID Association\n",
             ast_channel_name(audiosync->autochan->chan),
             audiosync->direction_string);
    ast_callid_threadassoc_add(audiosync->callid);
  }

  result = audiosync_fs_connect(audiosync);
  if (result != 0) {
    ast_log(LOG_ERROR, "<%s> Could not connect to sync: %s\n",
            ast_channel_name(audiosync->autochan->chan),
            audiosync->audiosync_ds->filename);

    ast_test_suite_event_notify("audiosync_END", "Ws server: %s\r\n",
                                audiosync->filename);

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

  size_t file_size = AUD_SYNC_INITIAL_FILE_SIZE;  // Define an appropriate initial size
if (ftruncate(audiosync->audio_fd, file_size) == -1) {
    ast_log(LOG_ERROR, "Failed to set file size: %s\n", strerror(errno));
    close(audiosync->audio_fd);
    return -1;
}

  ast_mutex_lock(&audiosync->audiosync_ds->lock);
  format_slin =
      ast_format_cache_get_slin_by_rate(audiosync->audiosync_ds->samp_rate);

  ast_mutex_unlock(&audiosync->audiosync_ds->lock);

  /* The audiohook must enter and exit the loop locked */
  ast_audiohook_lock(&audiosync->audiohook);

  void *mapped_region = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, audiosync->audio_fd, 0);
if (mapped_region == MAP_FAILED) {
    ast_log(LOG_ERROR, "mmap failed: %s\n", strerror(errno));
    close(audiosync->audio_fd);
    return -1 ;
}

  size_t offset = 0; 

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

      if (offset + cur->datalen > file_size) {
        ast_verb(2,
              "<%s> [audiosync] (%s) GOT BIGGER frame (len=%lu) \n",
              ast_channel_name(audiosync->autochan->chan),
              audiosync->direction_string, cur->datalen);
	if (msync(mapped_region, file_size, MS_SYNC) == -1) {
	    ast_log(LOG_ERROR, "msync failed: %s\n", strerror(errno));
                continue;
	}

	if (munmap(mapped_region, file_size) == -1) {
                ast_log(LOG_ERROR, "munmap failed: %s\n", strerror(errno));
                continue;
        }
        file_size *= 2;
	if (ftruncate(audiosync->audio_fd, file_size) == -1) {
            ast_log(LOG_ERROR, "Failed to extend file size: %s\n", strerror(errno));
            // close(audiosync->audio_fd);
            continue;
        }

        // Remap the extended file
        mapped_region = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, audiosync->audio_fd, 0);
        if (mapped_region == MAP_FAILED) {
            ast_log(LOG_ERROR, "mmap failed after remap: %s\n", strerror(errno));
            // close(audiosync->audio_fd);
            continue;
        }
      }

      // audiosync->audio_mmap = mapped_region;
      ast_verb(2,
              "<%s> [audiosync] (%s) Received audio data to write (len=%lu) \n",
              ast_channel_name(audiosync->autochan->chan),
              audiosync->direction_string, cur->datalen);
      memcpy(mapped_region + offset, cur->data.ptr, cur->datalen);
      // ssize_t bytes_written =
      //    write(audiosync->audio_fd, cur->data.ptr, cur->datalen);
      offset += cur->datalen;
      ast_verb(
          2,
          "<%s> [audiosync] (%s) Written %d bytes audio data to memory (%s) \n",
          ast_channel_name(audiosync->autochan->chan),
          audiosync->direction_string, offset, audiosync->filename);
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

  ast_verb(
    2,
    "<%s> [audiosync] (%s) Written %d bytes, fsz=%d audio data to memory \n",
    ast_channel_name(audiosync->autochan->chan),
    audiosync->direction_string, offset, file_size);
  if (msync(mapped_region, offset, MS_SYNC) == -1) {
      ast_log(LOG_ERROR, "msync failed: %s\n", strerror(errno));
  }
  
  ast_verb(
    2,
    "<%s> [audiosync] (%s) dumping %d bytes, fsz=%d audio data to memory \n",
    ast_channel_name(audiosync->autochan->chan),
    audiosync->direction_string, offset, file_size);
  if (munmap(mapped_region, file_size) == -1) {
      ast_log(LOG_ERROR, "munmap failed: %s\n", strerror(errno));
  }

  ast_audiohook_unlock(&audiosync->audiohook);

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

  // audiosync->name
  ast_verb(2, "<%s> [audiosync] (%s) End audiosync Recording\n",
           channel_name_cleanup, audiosync->direction_string);
  ast_test_suite_event_notify("audiosync_END", "END \r\n");

  /* free any audiosync memory */
  audiosync_free(audiosync);

  ast_module_unref(ast_module_info->self);

  return NULL;
}

static int setup_audiosync_ds(struct audiosync *audiosync,
                              struct ast_channel *chan, char **datastore_id) {
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

  audiosync_ds->samp_rate = 8000;
  audiosync_ds->audiohook = &audiosync->audiohook;
  audiosync_ds->filename = ast_strdup(audiosync->filename);
  datastore->data = audiosync_ds;

  ast_channel_lock(chan);
  ast_channel_datastore_add(chan, datastore);
  ast_channel_unlock(chan);

  audiosync->audiosync_ds = audiosync_ds;
  return 0;
}

static int launch_audiosync_thread(struct ast_channel *chan,
                                   const char *filename, unsigned int flags,
                                   enum ast_audiohook_direction direction,
                                   const char *uid_channel_var) {
  pthread_t thread;
  struct audiosync *audiosync;
  char *datastore_id = NULL;

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

  /* Server */
  if (!ast_strlen_zero(filename)) {
    ast_verb(2, "<%s> [audiosync] (%s) Setting audio filename: %s\n",
             ast_channel_name(chan), audiosync->direction_string, filename);
    audiosync->filename = ast_strdup(filename);
  }

  if (setup_audiosync_ds(audiosync, chan, &datastore_id)) {
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

  ast_set_flag(&audiosync->audiohook, AST_AUDIOHOOK_TRIGGER_SYNC);

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
  int x;
  char *uid_channel_var = NULL;
  unsigned int direction = 2;

  struct ast_flags flags = {0};
  char *parse;
  AST_DECLARE_APP_ARGS(args, AST_APP_ARG(filename); AST_APP_ARG(options););

  ast_log(LOG_NOTICE, "audiosync created with args %s\n", data);
  if (ast_strlen_zero(data)) {
    ast_log(LOG_WARNING, "audiosync requires an argument filename\n");
    return -1;
  }

  parse = ast_strdupa(data);

  AST_STANDARD_APP_ARGS(args, parse);

  if (args.options) {
    char *opts[OPT_ARG_ARRAY_SIZE] = {
        NULL,
    };

    ast_app_parse_options(audiosync_opts, &flags, opts, args.options);

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
  }

  /* If there are no file writing arguments/options for the mix monitor, send a
   * warning message and return -1 */

  if (ast_strlen_zero(args.filename)) {
    ast_log(LOG_WARNING, "audiosync requires an argument (filename)\n");
    return -1;
  }

  pbx_builtin_setvar_helper(chan, "audiosync_WSSERVER", args.filename);

  /* If launch_monitor_thread works, the module reference must not be released
   * until it is finished. */
  ast_module_ref(ast_module_info->self);

  if (launch_audiosync_thread(chan, args.filename, flags.flags, direction,
                              uid_channel_var)) {

    /* Failed */
    ast_module_unref(ast_module_info->self);
  }

  return 0;
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

  if (!ast_strlen_zero(args.key)) {
    ast_copy_string(buf, ds_data->filename, len);
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

static int set_audiosync_methods(void) { return 0; }

static int clear_audiosync_methods(void) { return 0; }

static int unload_module(void) {
  int res;

  // ast_cli_unregister_multiple(cli_audiosync, ARRAY_LEN(cli_audiosync));
  res = ast_unregister_application(app);
  res |= ast_custom_function_unregister(&audiosync_function);
  res |= clear_audiosync_methods();

  return res;
}

static int load_module(void) {
  int res;

  // ast_cli_register_multiple(cli_audiosync, ARRAY_LEN(cli_audiosync));
  res = ast_register_application_xml(app, audiosync_exec);
  res |= ast_custom_function_register(&audiosync_function);
  res |= set_audiosync_methods();

  return res;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
                "Audio Forking application",
                .support_level = AST_MODULE_SUPPORT_CORE, .load = load_module,
                .unload = unload_module,
                .optional_modules = "func_periodic_hook", );
