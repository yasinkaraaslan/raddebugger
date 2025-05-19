// Copyright (c) 2024 Epic Games Tools
// Licensed under the MIT license (https://opensource.org/license/mit/)

////////////////////////////////
//~ rjf: Build Options

#define BUILD_TITLE "ryan_scratch"
#define OS_FEATURE_GRAPHICAL 1

////////////////////////////////
//~ rjf: Includes

//- rjf: [lib]
#include "lib_rdi_format/rdi_format.h"
#include "lib_rdi_format/rdi_format.c"
#include "third_party/rad_lzb_simple/rad_lzb_simple.h"
#include "third_party/rad_lzb_simple/rad_lzb_simple.c"

//- rjf: [h]
#include "base/base_inc.h"
#include "os/os_inc.h"

//- rjf: [c]
#include "base/base_inc.c"
#include "os/os_inc.c"

////////////////////////////////
//~ rjf: Entry Points

internal B32
frame(void)
{
  B32 quit = 0;
  Temp scratch = scratch_begin(0, 0);
  OS_EventList events = os_get_events(scratch.arena, 0);
  for(OS_Event *ev = events.first; ev != 0; ev = ev->next)
  {
    if(ev->kind != OS_EventKind_MouseMove)
    {
      String8 string = push_str8f(scratch.arena, "%S (%S)\n", os_string_from_event_kind(ev->kind), os_g_key_display_string_table[ev->key]);
      printf("%.*s", str8_varg(string));
      raddbg_log((char *)string.str);
      fflush(stdout);
    }
    if(ev->kind == OS_EventKind_Press && ev->key == OS_Key_X)
    {
      *(volatile int *)0 = 0;
    }
  }
  for(OS_Event *ev = events.first; ev != 0; ev = ev->next)
  {
    if(ev->kind == OS_EventKind_WindowClose)
    {
      quit = 1;
      break;
    }
  }
  scratch_end(scratch);
  return quit;
}

internal void
entry_point(CmdLine *cmdline)
{
  OS_Handle window = os_window_open(r2f32p(0, 0, 1280, 720), OS_WindowFlag_UseDefaultPosition, str8_lit("Window"));
  os_window_first_paint(window);
  for(;!update(););
}
