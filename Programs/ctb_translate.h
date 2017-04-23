/*
 * BRLTTY - A background process providing access to the console screen (when in
 *          text mode) for a blind person using a refreshable braille display.
 *
 * Copyright (C) 1995-2017 by The BRLTTY Developers.
 *
 * BRLTTY comes with ABSOLUTELY NO WARRANTY.
 *
 * This is free software, placed under the terms of the
 * GNU General Public License, as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version. Please see the file LICENSE-GPL for details.
 *
 * Web Page: http://brltty.com/
 *
 * This software is maintained by Dave Mielke <dave@mielke.cc>.
 */

#ifndef BRLTTY_INCLUDED_CTB_TRANSLATE
#define BRLTTY_INCLUDED_CTB_TRANSLATE

#include "ctb.h"
#include "ctb_internal.h"
#include "prefs.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
  ContractionTable *const table;

  struct {
    const wchar_t *begin;
    const wchar_t *end;
    const wchar_t *current;
    const wchar_t *cursor;
    int *offsets;
  } input;

  struct {
    BYTE *begin;
    BYTE *end;
    BYTE *current;
  } output;

  struct {
    const ContractionTableRule *rule;
    ContractionTableOpcode opcode;
    int length;

    wchar_t before;
    wchar_t after;
  } current;

  struct {
    ContractionTableOpcode opcode;
  } previous;
} BrailleContractionData;

static inline unsigned int
getInputCount (BrailleContractionData *bcd) {
  return bcd->input.end - bcd->input.begin;
}

static inline unsigned int
getInputConsumed (BrailleContractionData *bcd) {
  return bcd->input.current - bcd->input.begin;
}

static inline unsigned int
getInputUnconsumed (BrailleContractionData *bcd) {
  return bcd->input.end - bcd->input.current;
}

static inline unsigned int
getOutputCount (BrailleContractionData *bcd) {
  return bcd->output.end - bcd->output.begin;
}

static inline unsigned int
getOutputConsumed (BrailleContractionData *bcd) {
  return bcd->output.current - bcd->output.begin;
}

static inline void
assignOffset (BrailleContractionData *bcd, size_t value) {
  if (bcd->input.offsets) bcd->input.offsets[getInputConsumed(bcd)] = value;
}

static inline void
setOffset (BrailleContractionData *bcd) {
  assignOffset(bcd, getOutputConsumed(bcd));
}

static inline void
clearOffset (BrailleContractionData *bcd) {
  assignOffset(bcd, CTB_NO_OFFSET);
}

extern CharacterEntry *getCharacterEntry (BrailleContractionData *bcd, wchar_t character);

static inline int
testCharacter (BrailleContractionData *bcd, wchar_t character, ContractionTableCharacterAttributes attributes) {
  const CharacterEntry *entry = getCharacterEntry(bcd, character);
  return entry && (attributes & entry->attributes);
}

static inline int
testRelative (BrailleContractionData *bcd, int offset, ContractionTableCharacterAttributes attributes) {
  return testCharacter(bcd, bcd->input.current[offset], attributes);
}

static inline int
testCurrent (BrailleContractionData *bcd, ContractionTableCharacterAttributes attributes) {
  return testRelative(bcd, 0, attributes);
}

static inline int
testPrevious (BrailleContractionData *bcd, ContractionTableCharacterAttributes attributes) {
  return testRelative(bcd, -1, attributes);
}

static inline int
testNext (BrailleContractionData *bcd, ContractionTableCharacterAttributes attributes) {
  return testRelative(bcd, 1, attributes);
}

static inline int
testBefore (BrailleContractionData *bcd, ContractionTableCharacterAttributes attributes) {
  return testCharacter(bcd, bcd->current.before, attributes);
}

static inline int
testAfter (BrailleContractionData *bcd, ContractionTableCharacterAttributes attributes) {
  return testCharacter(bcd, bcd->current.after, attributes);
}

typedef int ContractTextFunction (BrailleContractionData *bcd);
extern ContractTextFunction contractText_native;
extern ContractTextFunction contractText_external;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BRLTTY_INCLUDED_CTB_TRANSLATE */
