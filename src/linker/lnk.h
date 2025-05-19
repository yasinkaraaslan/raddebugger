// Copyright (c) 2025 Epic Games Tools
// Licensed under the MIT license (https://opensource.org/license/mit/)

#pragma once

// --- CRT Symbols -------------------------------------------------------------

// _load_config_used points to PE_LoadConfig32/PE_LoadConfig64
// and symbols below are used to patch patricual fields of the struct.
#define LNK_LOAD_CONFIG_SYMBOL_NAME         "_load_config_used"
#define LNK_ENCLAVE_CONFIG_SYMBOL_NAME      "__enclave_config"
#define LNK_GUARD_FLAGS_SYMBOL_NAME         "__guard_flags"
#define LNK_GUARD_FIDS_TABLE_SYMBOL_NAME    "__guard_fids_table"
#define LNK_GUARD_FIDS_COUNT_SYMBOL_NAME    "__guard_fids_count"
#define LNK_GUARD_IAT_TABLE_SYMBOL_NAME     "__guard_iat_table"
#define LNK_GUARD_IAT_COUNT_SYMBOL_NAME     "__guard_iat_count"
#define LNK_GUARD_LONGJMP_TABLE_SYMBOL_NAME "__guard_longjmp_table"
#define LNK_GUARD_LONGJMP_COUNT_SYMBOL_NAME "__guard_longjmp_count"
#define LNK_GUARD_EHCONT_TABLE_SYMBOL_NAME  "__guard_eh_cont_table"
#define LNK_GUARD_EHCONT_COUNT_SYMBOL_NAME  "__guard_eh_cont_count"

// x86 load config fields
#define LNK_SAFE_SE_HANDLER_TABLE_SYMBOL_NAME "__safe_se_handler_table"
#define LNK_SAFE_SE_HANDLER_COUNT_SYMBOL_NAME "__safe_se_handler_count"

// load symbols from delayimp.lib
#define LNK_DELAY_LOAD_HELPER2_SYMBOL_NAME     "__delayLoadHelper2"
#define LNK_DELAY_LOAD_HELPER2_X86_SYMBOL_NAME "___delayLoadHelper2@8"

// _tls_used is a special section in CRT which has format of 
// PE_TLSHeader32 or PE_TLSHeader64, according to machine type.
#define LNK_TLS_SYMBOL_NAME "_tls_used"

// --- Base Reloc --------------------------------------------------------------

typedef struct LNK_BaseRelocPage
{
  U64     voff;
  U64List entries_addr32;
  U64List entries_addr64;
} LNK_BaseRelocPage;

typedef struct LNK_BaseRelocPageNode
{
  struct LNK_BaseRelocPageNode *next;
  LNK_BaseRelocPage             v;
} LNK_BaseRelocPageNode;

typedef struct LNK_BaseRelocPageList
{
  U64                    count;
  LNK_BaseRelocPageNode *first;
  LNK_BaseRelocPageNode *last;
} LNK_BaseRelocPageList;

typedef struct LNK_BaseRelocPageArray
{
  U64                count;
  LNK_BaseRelocPage *v;
} LNK_BaseRelocPageArray;

// --- Workers Contexts --------------------------------------------------------

typedef struct
{
  U64                     page_size;
  Rng1U64                *range_arr;
  LNK_BaseRelocPageList  *list_arr;
  HashTable             **page_ht_arr;
  B32                     is_large_addr_aware;
} LNK_BaseRelocTask;

typedef struct
{
  Rng1U64                *ranges;
  U64                     page_size;
  LNK_BaseRelocPageList  *list_arr;
  LNK_Obj               **obj_arr;
  HashTable             **page_ht_arr;
  B32                     is_large_addr_aware;
} LNK_ObjBaseRelocTask;

typedef struct
{
  LNK_InputObjList    input_obj_list;
  U64                 input_imports_count;
  LNK_InputImport    *input_imports;
  LNK_InputImportList input_import_list;
  LNK_SymbolList      unresolved_symbol_list;
} LNK_SymbolFinderResult;

typedef struct
{
  PathStyle               path_style;
  LNK_SymbolTable        *symtab;
  LNK_SymbolNodeArray     lookup_node_arr;
  LNK_SymbolFinderResult *result_arr;
  Rng1U64                *range_arr;
} LNK_SymbolFinder;

typedef struct
{
  String8              image_data;
  LNK_Obj            **objs;
  U64                  image_base;
  COFF_SectionHeader **image_section_table;
} LNK_ObjRelocPatcher;

typedef struct
{
  String8 path;
  String8 temp_path;
  String8 data;
} LNK_WriteThreadContext;

typedef struct
{
  String8  data;
  Rng1U64 *ranges;
  U128    *hashes;
} LNK_Blake3Hasher;

typedef struct
{
  LNK_SymbolTable  *symtab;
  union {
    LNK_ObjNodeArray objs;
    LNK_LibNodeArray libs;
  } u;
} LNK_SymbolPusher;

// --- Entry Point -------------------------------------------------------------

internal void lnk_run(int argc, char **argv);

// --- Path --------------------------------------------------------------------

internal String8 lnk_make_full_path(Arena *arena, PathStyle system_path_style, String8 work_dir, String8 path);

// --- Hasher ------------------------------------------------------------------

internal U128 lnk_blake3_hash_parallel(TP_Context *tp, U64 chunk_count, String8 data);

// --- Manifest ----------------------------------------------------------------

internal String8 lnk_make_linker_manifest(Arena *arena, B32 manifest_uac, String8 manifest_level, String8 manifest_ui_access, String8List manifest_dependency_list);
internal void    lnk_merge_manifest_files(String8 mt_path, String8 out_name, String8List manifest_path_list);
internal String8 lnk_manifest_from_inputs(Arena *arena, String8 mt_path, String8 manifest_name, B32 manifest_uac, String8 manifest_level, String8 manifest_ui_access, String8List input_manifest_path_list, String8List deps_list);

// --- Internal Objs -----------------------------------------------------------

internal String8 lnk_make_res_obj(Arena *arena, String8List res_file_list, String8List res_path_list, COFF_MachineType machine, U32 time_stamp, String8 work_dir, PathStyle system_path_style, String8 obj_name);
internal String8 lnk_make_linker_coff_obj(Arena *arena, COFF_TimeStamp time_stamp, COFF_MachineType machine, String8 cwd_path, String8 exe_path, String8 pdb_path, String8 cmd_line, String8 obj_name);
internal String8 lnk_make_debug_directory_obj(Arena *arena, LNK_Config *config);
internal String8 lnk_make_debug_directory_pdb_obj(Arena *arena, LNK_Config *config);
internal String8 lnk_make_debug_directory_rdi_obj(Arena *arena, LNK_Config *config);

// --- Symbol Resolver ---------------------------------------------------------

internal String8 lnk_get_lib_name(String8 path);
internal B32     lnk_is_lib_disallowed(HashTable *disallow_lib_ht, String8 path);
internal B32     lnk_is_lib_loaded(HashTable *loaded_lib_ht, String8 lib_path);
internal void    lnk_push_disallow_lib(Arena *arena, HashTable *disallow_lib_ht, String8 path);
internal void    lnk_push_loaded_lib(Arena *arena, HashTable *loaded_lib_ht, String8 path);

internal LNK_InputObjList lnk_push_linker_symbols(Arena *arena, LNK_Config *config);
internal void             lnk_queue_lib_member_input(Arena *arena, PathStyle path_style, LNK_SymbolLib *symbol, LNK_InputImportList *input_import_list, LNK_InputObjList *input_obj_list);

// --- Win32 Image -------------------------------------------------------------

internal String8List lnk_build_guard_tables(TP_Context *tp, LNK_SectionTable *sectab, LNK_SymbolTable *symtab, U64 objs_count, LNK_Obj **objs, COFF_MachineType machine, String8 entry_point_name, LNK_GuardFlags guard_flags, B32 emit_suppress_flag);
internal String8List lnk_build_base_relocs(TP_Context *tp, TP_Arena *tp_temp, LNK_Config *config, U64 objs_count, LNK_Obj **objs);
internal String8List lnk_build_win32_image_header(Arena *arena, LNK_SymbolTable *symtab, LNK_Config *config, LNK_SectionArray sect_arr, U64 expected_image_header_size);
internal String8     lnk_build_win32_image(TP_Arena *arena, TP_Context *tp, LNK_Config *config, LNK_SymbolTable *symtab, LNK_ObjList obj_list);

// --- Logger ------------------------------------------------------------------

internal void lnk_log_link_stats(LNK_ObjList obj_list, LNK_LibList *lib_index, LNK_SectionTable *sectab);
internal void lnk_log_timers(void);

