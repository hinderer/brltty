/*
 * BRLTTY - A background process providing access to the console screen (when in
 *          text mode) for a blind person using a refreshable braille display.
 *
 * Copyright (C) 1995-2014 by The BRLTTY Developers.
 *
 * BRLTTY comes with ABSOLUTELY NO WARRANTY.
 *
 * This is free software, placed under the terms of the
 * GNU General Public License, as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version. Please see the file LICENSE-GPL for details.
 *
 * Web Page: http://mielke.cc/brltty/
 *
 * This software is maintained by Dave Mielke <dave@mielke.cc>.
 */

#ifndef BRLTTY_INCLUDED_ALERT
#define BRLTTY_INCLUDED_ALERT

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  ALERT_NONE,
  ALERT_BRAILLE_ON,
  ALERT_BRAILLE_OFF,
  ALERT_COMMAND_DONE,
  ALERT_COMMAND_REJECTED,
  ALERT_MARK_SET,
  ALERT_CLIPBOARD_BEGIN,
  ALERT_CLIPBOARD_END,
  ALERT_NO_CHANGE,
  ALERT_TOGGLE_ON,
  ALERT_TOGGLE_OFF,
  ALERT_CURSOR_LINKED,
  ALERT_CURSOR_UNLINKED,
  ALERT_SCREEN_FROZEN,
  ALERT_SCREEN_UNFROZEN,
  ALERT_WRAP_DOWN,
  ALERT_WRAP_UP,
  ALERT_SKIP_FIRST,
  ALERT_SKIP,
  ALERT_SKIP_MORE,
  ALERT_BOUNCE,
  ALERT_ROUTING_STARTED,
  ALERT_ROUTING_SUCCEEDED,
  ALERT_ROUTING_FAILED,
  ALERT_FREEZE_REMINDER
} AlertIdentifier;

extern void alert (AlertIdentifier identifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BRLTTY_INCLUDED_ALERT */
