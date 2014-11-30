/*
 * BRLTTY - A background process providing access to the console screen (when in
 *          text mode) for a blind person using a refreshable braille display.
 *
 * Copyright (C) 1995-2015 by The BRLTTY Developers.
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

/** EuroBraille/eu_clio.c 
 ** Implements the NoteBraille/Clio/Scriba/Iris <= 1.70 protocol 
 ** Made by Olivier BER` <obert01@mistigri.org>
 */

#include "prologue.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "timing.h"
#include "ascii.h"
#include "brldefs-eu.h"
#include "eu_protocol.h"

#define BRAILLE_KEY_ENTRY(k,n) KEY_ENTRY(BrailleKeys, DOT, k, n)
#define NAVIGATION_KEY_ENTRY(k,n) KEY_ENTRY(NavigationKeys, NAV, k, n)
#define INTERACTIVE_KEY_ENTRY(k,n) KEY_ENTRY(InteractiveKeys, INT, k, n)

BEGIN_KEY_NAME_TABLE(braille)
  BRAILLE_KEY_ENTRY(1, "Dot1"),
  BRAILLE_KEY_ENTRY(2, "Dot2"),
  BRAILLE_KEY_ENTRY(3, "Dot3"),
  BRAILLE_KEY_ENTRY(4, "Dot4"),
  BRAILLE_KEY_ENTRY(5, "Dot5"),
  BRAILLE_KEY_ENTRY(6, "Dot6"),
  BRAILLE_KEY_ENTRY(7, "Dot7"),
  BRAILLE_KEY_ENTRY(8, "Dot8"),
  BRAILLE_KEY_ENTRY(B, "Backspace"),
  BRAILLE_KEY_ENTRY(S, "Space"),
END_KEY_NAME_TABLE

BEGIN_KEY_NAME_TABLE(function)
  NAVIGATION_KEY_ENTRY(E, "E"),
  NAVIGATION_KEY_ENTRY(F, "F"),
  NAVIGATION_KEY_ENTRY(G, "G"),
  NAVIGATION_KEY_ENTRY(H, "H"),
  NAVIGATION_KEY_ENTRY(I, "I"),
  NAVIGATION_KEY_ENTRY(J, "J"),
  NAVIGATION_KEY_ENTRY(K, "K"),
  NAVIGATION_KEY_ENTRY(L, "L"),
  NAVIGATION_KEY_ENTRY(M, "M"),
END_KEY_NAME_TABLE

BEGIN_KEY_NAME_TABLE(keypad)
  NAVIGATION_KEY_ENTRY(One, "One"),
  NAVIGATION_KEY_ENTRY(Two, "Up"),
  NAVIGATION_KEY_ENTRY(Three, "Three"),
  NAVIGATION_KEY_ENTRY(A, "A"),

  NAVIGATION_KEY_ENTRY(Four, "Left"),
  NAVIGATION_KEY_ENTRY(Five, "Five"),
  NAVIGATION_KEY_ENTRY(Six, "Right"),
  NAVIGATION_KEY_ENTRY(B, "B"),

  NAVIGATION_KEY_ENTRY(Seven, "Seven"),
  NAVIGATION_KEY_ENTRY(Eight, "Down"),
  NAVIGATION_KEY_ENTRY(Nine, "Nine"),
  NAVIGATION_KEY_ENTRY(C, "C"),

  NAVIGATION_KEY_ENTRY(Star, "Star"),
  NAVIGATION_KEY_ENTRY(Zero, "Zero"),
  NAVIGATION_KEY_ENTRY(Sharp, "Sharp"),
  NAVIGATION_KEY_ENTRY(D, "D"),
END_KEY_NAME_TABLE

BEGIN_KEY_NAME_TABLE(interactive)
  INTERACTIVE_KEY_ENTRY(Dollar, "Dollar"),
  KEY_GROUP_ENTRY(EU_GRP_RoutingKeys1, "RoutingKey"),
  INTERACTIVE_KEY_ENTRY(U, "U"),
  INTERACTIVE_KEY_ENTRY(V, "V"),
  INTERACTIVE_KEY_ENTRY(W, "W"),
  INTERACTIVE_KEY_ENTRY(X, "X"),
  INTERACTIVE_KEY_ENTRY(Y, "Y"),
  INTERACTIVE_KEY_ENTRY(Z, "Z"),
END_KEY_NAME_TABLE

BEGIN_KEY_NAME_TABLES(clio)
  KEY_NAME_TABLE(braille),
  KEY_NAME_TABLE(function),
  KEY_NAME_TABLE(keypad),
  KEY_NAME_TABLE(interactive),
END_KEY_NAME_TABLES

PUBLIC_KEY_TABLE(clio)

#define	INPUT_BUFFER_SIZE 1024
#define MAXIMUM_DISPLAY_SIZE 80
#define MAXPACKETSIZE 255

typedef struct {
  char modelCode[3];
  const char *modelName;
  unsigned char cellCount;
  unsigned isAzerBraille:1;
  unsigned isEuroBraille:1;
  unsigned isIris:1;
  unsigned isNoteBraille:1;
  unsigned isPupiBraille:1;
  unsigned isScriba:1;
  unsigned hasRoutingKeys:1;
  unsigned hasVisualDisplay:1;
} ModelEntry;

static const ModelEntry modelTable[] = {
  { .modelCode = "CE2",
    .modelName = "Clio-EuroBraille 20",
    .cellCount = 20,
    .hasRoutingKeys = 1,
    .isEuroBraille = 1
  },

  { .modelCode = "CE4",
    .modelName = "Clio-EuroBraille 40",
    .cellCount = 40,
    .hasRoutingKeys = 1,
    .isEuroBraille = 1
  },

  { .modelCode = "CE8",
    .modelName = "Clio-EuroBraille 80",
    .cellCount = 80,
    .hasRoutingKeys = 1,
    .isEuroBraille = 1
  },

  { .modelCode = "CN2",
    .modelName = "Clio-NoteBraille 20",
    .cellCount = 20,
    .hasRoutingKeys = 1,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "CN4",
    .modelName = "Clio-NoteBraille 40",
    .cellCount = 40,
    .hasRoutingKeys = 1,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "CN8",
    .modelName = "Clio-NoteBraille 80",
    .cellCount = 80,
    .hasRoutingKeys = 1,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "Cp2",
    .modelName = "Clio-PupiBraille 20",
    .cellCount = 20,
    .hasRoutingKeys = 1,
    .isPupiBraille = 1
  },

  { .modelCode = "Cp4",
    .modelName = "Clio-PupiBraille 40",
    .cellCount = 40,
    .hasRoutingKeys = 1,
    .isPupiBraille = 1
  },

  { .modelCode = "Cp8",
    .modelName = "Clio-PupiBraille 80",
    .cellCount = 80,
    .hasRoutingKeys = 1,
    .isPupiBraille = 1
  },

  { .modelCode = "CZ4",
    .modelName = "Clio-AzerBraille 40",
    .cellCount = 40,
    .hasRoutingKeys = 1,
    .hasVisualDisplay = 1,
    .isAzerBraille = 1
  },

  { .modelCode = "JN2",
    .modelName = "Junior-NoteBraille 20",
    .cellCount = 20,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "NB2",
    .modelName = "NoteBraille 20",
    .cellCount = 20,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "NB4",
    .modelName = "NoteBraille 40",
    .cellCount = 40,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "NB8",
    .modelName = "NpoteBraille 80",
    .cellCount = 80,
    .hasVisualDisplay = 1,
    .isNoteBraille = 1
  },

  { .modelCode = "JS2",
    .modelName = "Junior-Scriba 20",
    .cellCount = 20,
    .hasRoutingKeys = 1,
    .isScriba = 1
  },

  { .modelCode = "SB2",
    .modelName = "Scriba 20",
    .cellCount = 20,
    .hasRoutingKeys = 1,
    .isScriba = 1
  },

  { .modelCode = "SB4",
    .modelName = "Scriba 40",
    .cellCount = 40,
    .hasRoutingKeys = 1,
    .isScriba = 1
  },

  { .modelCode = "SC2",
    .modelName = "Scriba 20",
    .cellCount = 20
  },

  { .modelCode = "SC4",
    .modelName = "Scriba 40",
    .cellCount = 40
  },

  { .modelCode = "IR2",
    .modelName = "Iris 20",
    .cellCount = 20,
    .hasVisualDisplay = 1,
    .isIris = 1
  },

  { .modelCode = "IR4",
    .modelName = "Iris 40",
    .cellCount = 40,
    .hasVisualDisplay = 1,
    .isIris = 1
  },

  { .modelCode = "IS2",
    .modelName = "Iris S20",
    .cellCount = 20,
    .isIris = 1
  },

  { .modelCode = "IS3",
    .modelName = "Iris S32",
    .cellCount = 32,
    .isIris = 1
  },

  { .modelCode = "" }
};

static int haveSystemInformation;
static unsigned char firmwareVersion[21];
static const ModelEntry *model;

static int forceWindowRewrite;
static int forceVisualRewrite;
static int forceCursorRewrite;
static int outputPacketNumber;

static inline void
forceRewrite (void) {
  forceWindowRewrite = 1;
  forceVisualRewrite = 1;
  forceCursorRewrite = 1;
}

static int
needsEscape (unsigned char byte) {
  switch (byte) {
    case SOH:
    case EOT:
    case DLE:
    case ACK:
    case NAK:
      return 1;
  }

  return 0;
}

typedef enum {
  PVS_PACKET_BEGIN,
  PVS_FRAME_SIZE,
  PVS_FRAME_CONTENT,
} PacketVerifierState;

static const char *packetVerifierStateName(PacketVerifierState state)
{
  switch (state) {
    case PVS_PACKET_BEGIN: return "PVS_PACKET_BEGIN";
    case PVS_FRAME_SIZE: return "PVS_FRAME_SIZE";
    case PVS_FRAME_CONTENT: return "PVS_FRAME_CONTENT";
  }

  return "unknown packet verifier state";
}

typedef struct {
  PacketVerifierState state;
  int escaped;
  unsigned int frameLength;
  unsigned int frameIndex;
  unsigned char checksum;
  unsigned char packetNumber;
} PacketVerifierData;

static BraillePacketVerifierResult
verifyPacket (
  BrailleDisplay *brl,
  const unsigned char *bytes, size_t size,
  size_t *length, void *data
) {
  PacketVerifierData *pvd = data;
  unsigned char byte = bytes[size-1];

  logMessage(LOG_CATEGORY(BRAILLE_DRIVER),
    "[eu] verifyPacket: state=%s, byte=0x%2x, size=%ld, length=%ld, frameLength=%d, frameIndex=%d",
    packetVerifierStateName(pvd->state),
    byte,
    size,
    *length,
    pvd->frameLength,
    pvd->frameIndex
  );

  if (pvd->state == PVS_PACKET_BEGIN) {
    if (byte != SOH) return BRL_PVR_INVALID;
    pvd->state = PVS_FRAME_SIZE;
    return BRL_PVR_EXCLUDE;
  }

  if (pvd->escaped) {
    pvd->escaped = 0;
  } else if (byte == DLE) {
    pvd->escaped = 1;
    return BRL_PVR_EXCLUDE;
  } else if ( (pvd->state == PVS_FRAME_CONTENT) &&
              (pvd->frameIndex == 1) && (byte == EOT) ) {
    int validPacket = ! pvd->checksum;

    {
      unsigned char response[] = { validPacket ? ACK : NAK };
      writeBraillePacket(brl, NULL, response, sizeof(response));
    }

    pvd->packetNumber = bytes[size-3];
    size -= 3; /* Remove packet number, packet checksum and end of packet */
    *length = size;
    return validPacket ? BRL_PVR_EXCLUDE : BRL_PVR_INVALID;
  } else if ( (byte == SOH) || (byte == EOT) ) {
    return BRL_PVR_INVALID;
  }

  switch (pvd->state) {
    case PVS_FRAME_SIZE:
      pvd->state = PVS_FRAME_CONTENT;
      pvd->frameLength = byte;
      pvd->frameIndex = 0;
      *length += pvd->frameLength + 1;
      break;

    case PVS_FRAME_CONTENT:
      pvd->frameIndex++;
      if (pvd->frameIndex == pvd->frameLength) pvd->state = PVS_FRAME_SIZE;
      break;

    default:
      logMessage(LOG_WARNING,
        "[eu] verifyPacket: unsupported state %s",
        packetVerifierStateName(pvd->state)
      );
      return BRL_PVR_INVALID;
  }

  pvd->checksum ^= byte;
  return BRL_PVR_INCLUDE;
}

static ssize_t
readPacket (BrailleDisplay *brl, void *packet, size_t size) {
  PacketVerifierData pvd = {
    .state = PVS_PACKET_BEGIN,
    .escaped = 0,
    .frameLength = 0,
    .frameIndex = 0,
    .checksum = 0,
    .packetNumber = 0,
  };

  return readBraillePacket(brl, NULL, packet, size, verifyPacket, &pvd);
}

static ssize_t
writePacket (BrailleDisplay *brl, const void *packet, size_t size) {
#define PUT(byte) \
  if (needsEscape((byte))) *target++ = DLE; \
  *target++ = (byte); \
  checksum ^= (byte);

  /* limit case, every char is escaped */
  unsigned char	buffer[(size + 4) * 2]; 
  unsigned char	*target = buffer;
  const unsigned char *source = packet;
  unsigned char	checksum = 0;

  *target++ = SOH;
  PUT(size);

  while (size--) {
    PUT(*source);
    source += 1;
  }

  PUT(outputPacketNumber);
  if (++outputPacketNumber >= 256) outputPacketNumber = 128;

  PUT(checksum);
  *target++ = EOT;

  {
    size_t count = target - buffer;
    logOutputPacket(buffer, count);
    return io->writeData(brl, buffer, count);
  }
#undef PUT
}

static int
resetDevice (BrailleDisplay *brl) {
  static const unsigned char packet[] = {'S', 'I'};
  return writePacket(brl, packet, sizeof(packet)) != -1;
}

static const ModelEntry *
getModelEntry (const unsigned char *code) {
  const ModelEntry *mdl = modelTable;

  while (mdl->modelCode[0]) {
    if (memcmp(mdl->modelCode, code, sizeof(mdl->modelCode)) == 0) return mdl;
    mdl += 1;
  }

  return NULL;
}

static void
handleSystemInformation (BrailleDisplay *brl, const unsigned char *packet) {
  const unsigned char *p = packet;

  while (1) {
    unsigned char length = *(p++);

    switch (p[0]) {
      case 'S':
        switch (p[1]) {
          case 'I': {
            unsigned char count = length - 2;
            if (count >= sizeof(firmwareVersion)) count = sizeof(firmwareVersion) - 1;
            memcpy(firmwareVersion, p+2, count);
            model = getModelEntry(firmwareVersion);
            return;
          }

          default:
            break;
        }
        break;

      default:
        break;
    }

    p += length;
  }
}

static int
writeWindow (BrailleDisplay *brl) {
  static unsigned char previousCells[MAXIMUM_DISPLAY_SIZE];
  size_t size = brl->textColumns * brl->textRows;
  unsigned char buffer[size + 2];

  if (cellsHaveChanged(previousCells, brl->buffer, size, NULL, NULL, &forceWindowRewrite)) {
    buffer[0] = 'D';
    buffer[1] = 'P';
    translateOutputCells(buffer+2, brl->buffer, size);
    writePacket(brl, buffer, sizeof(buffer));
  }

  return 1;
}

static int
writeVisual (BrailleDisplay *brl, const wchar_t *text) {
  if (model->hasVisualDisplay) {
    size_t size = brl->textColumns * brl->textRows;
    int changed = 0;

    {
      static wchar_t previousText[MAXIMUM_DISPLAY_SIZE];

      if (textHasChanged(previousText, text, size, NULL, NULL, &forceVisualRewrite)) changed = 1;
    }

    {
      static int previousCursor;

      if (cursorHasChanged(&previousCursor, brl->cursor, &forceCursorRewrite)) changed = 1;
    }

    if (changed) {
      const wchar_t *source = text;
      const wchar_t *end = source + size;
      const wchar_t *cursor = (brl->cursor >= 0)? source+brl->cursor: NULL;

      unsigned char buffer[size + 4]; // code, subcode, and possibly two bytes for cursor
      unsigned char *target = buffer;

      *target++ = 'D';
      *target++ = 'L';

      while (source < end) {
        if (source == cursor) {
          *target++ = ESC;
          *target++ = EU_LCD_CURSOR;
        }

        {
          wchar_t wc = *source++;
          if (!iswLatin1(wc)) wc = '?';
          *target++ = wc;
        }
      }

      writePacket(brl, buffer, target-buffer);
    }
  }

  return 1;
}

static int
hasVisualDisplay (BrailleDisplay *brl) {
  return model->hasVisualDisplay;
}

static int
handleMode (BrailleDisplay *brl, const unsigned char *packet) {
  if (*packet == 'B') {
    forceRewrite();
    return 1;
  }

  return 0;
}

static int
handleKeyEvent (BrailleDisplay *brl, const unsigned char *packet) {
  switch (packet[0]) {
    case 'B': {
      KeyNumberSet keys = ((packet[2] << 8) | packet[1]) & 0X3FF;

      enqueueKeys(brl, keys, EU_GRP_BrailleKeys, 0);
      return 1;
    }

    case 'I': {
      unsigned char key = packet[1];

      if ((key >= 1) && (key <= brl->textColumns)) {
        enqueueKey(brl, EU_GRP_RoutingKeys1, key-1);
      } else {
        enqueueKey(brl, EU_GRP_InteractiveKeys, key);
      }

      return 1;
    }

    case 'T': 
      enqueueKey(brl, EU_GRP_NavigationKeys, packet[1]);
      return 1;

    default :
      break;
  }

  return 0;
}

static int
readCommand (BrailleDisplay *brl, KeyTableCommandContext ctx) {
  unsigned char	packet[INPUT_BUFFER_SIZE];
  ssize_t length;

  while ((length = readPacket(brl, packet, sizeof(packet))) > 0) {
    switch (packet[1]) {
      case 'S': 
        handleSystemInformation(brl, packet);
        haveSystemInformation = 1;
        continue;

      case 'R': 
        if (handleMode(brl, packet+2)) continue;
        break;

      case 'K': 
        if (handleKeyEvent(brl, packet+2)) continue;
        break;

      default: 
        break;
    }

    logUnexpectedPacket(packet, length);
  }

  return (length == -1)? BRL_CMD_RESTARTBRL: EOF;
}

static int
initializeDevice (BrailleDisplay *brl) {
  int retriesLeft = 2;

  haveSystemInformation = 0;
  memset(firmwareVersion, 0, sizeof(firmwareVersion));
  model = NULL;

  forceRewrite();
  outputPacketNumber = 127;

  do {
    if (!resetDevice(brl)) return 0;

    while (io->awaitInput(brl, 500)) {
      if (readCommand(brl, KTB_CTX_DEFAULT) == BRL_CMD_RESTARTBRL) return 0;

      if (haveSystemInformation) {
        if (!model) {
          int length = sizeof(model->modelCode);
          logMessage(LOG_WARNING, "unknown EuroBraille model: %.*s",
                     length, firmwareVersion);
          return 0;
        }

        brl->textColumns = model->cellCount;

        switch (firmwareVersion[2]) {
          case '2':
            brl->textColumns = 20;
            break;

          case '3':
            brl->textColumns = 32;
            break;

          case '4':
            brl->textColumns = 40;
            break;

          case '8':
            brl->textColumns = 80;
            break;

          default:
            break;
        }

        {
          const KeyTableDefinition *ktd = &KEY_TABLE_DEFINITION(clio);
          brl->keyBindings = ktd->bindings;
          brl->keyNames = ktd->names;
        }

        logMessage(LOG_INFO, "Model Detected: %s (%u cells)",
                   model->modelName, brl->textColumns);
        return 1;
      }
    }
  } while (retriesLeft-- && (errno == EAGAIN));

  return 0;
}

const ProtocolOperations clioProtocolOperations = {
  .protocolName = "clio",

  .initializeDevice = initializeDevice,
  .resetDevice = resetDevice,

  .readPacket = readPacket,
  .writePacket = writePacket,

  .readCommand = readCommand,
  .writeWindow = writeWindow,

  .hasVisualDisplay = hasVisualDisplay,
  .writeVisual = writeVisual
};
