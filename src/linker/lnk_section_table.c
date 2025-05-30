// Copyright (c) 2025 Epic Games Tools
// Licensed under the MIT license (https://opensource.org/license/mit/)

internal U8
lnk_code_align_byte_from_machine(COFF_MachineType machine)
{
  U8 align_byte = 0;
  switch (machine) {
  case COFF_MachineType_X64:
  case COFF_MachineType_X86: {
    align_byte = 0xCC;
  } break;
  default: {
    lnk_not_implemented("TODO: set align value for machine %S", coff_string_from_machine_type(machine));
  } break;
  }
  return align_byte;
}

internal U16
lnk_default_align_from_machine(COFF_MachineType machine)
{
  U16 align = 0;
  switch (machine) {
  case COFF_MachineType_Unknown: break;
  case COFF_MachineType_X64: {
    align = 16;
  } break;
  default: { NotImplemented; } break;
  }
  return align;
}

internal LNK_SectionContrib *
lnk_section_contrib_chunk_push(LNK_SectionContribChunk *chunk, U64 count)
{
  Assert(chunk->count + count <= chunk->cap);
  LNK_SectionContrib *result = chunk->v[chunk->count];
  chunk->count += count;
  return result;
}

internal LNK_SectionContribChunk *
lnk_section_contrib_chunk_list_push_chunk(Arena *arena, LNK_SectionContribChunkList *list, U64 cap)
{
  LNK_SectionContribChunk *chunk = push_array(arena, LNK_SectionContribChunk, 1);
  chunk->count = 0;
  chunk->cap   = cap;
  chunk->v     = push_array(arena, LNK_SectionContrib *, cap);
  chunk->v2 = push_array(arena, LNK_SectionContrib, cap);
  for (U64 i = 0; i < cap; i += 1) { chunk->v[i] = &chunk->v2[i]; }
  SLLQueuePush(list->first, list->last, chunk);
  list->chunk_count += 1;
  return chunk;
}

internal void
lnk_section_contrib_chunk_list_concat_in_place(LNK_SectionContribChunkList *list, LNK_SectionContribChunkList *to_concat)
{
  if (list->chunk_count == 0) {
    *list = *to_concat;
  } else {
    list->last->next   = to_concat->first;
    list->last         = to_concat->last;
    list->chunk_count += to_concat->chunk_count;
  }
}

internal LNK_SectionArray
lnk_section_array_from_list(Arena *arena, LNK_SectionList list)
{
  LNK_SectionArray result;
  result.count = 0;
  result.v = push_array_no_zero(arena, LNK_Section *, list.count);
  for (LNK_SectionNode *node = list.first; node != 0; node = node->next) {
    result.v[result.count] = &node->data;
    result.count += 1;
  }
  return result;
}

internal U64
lnk_voff_from_section_contrib(COFF_SectionHeader **image_section_table, LNK_SectionContrib *sc)
{
  COFF_SectionHeader *sect_header = image_section_table[sc->u.sect_idx+1];
  U64 voff = sect_header->voff + sc->u.off;
  return voff;
}

internal U64
lnk_foff_from_section_contrib(COFF_SectionHeader **image_section_table, LNK_SectionContrib *sc)
{
  COFF_SectionHeader *sect_header = image_section_table[sc->u.sect_idx+1];
  U64 foff = sect_header->foff + sc->u.off;
  return foff;
}

internal U64
lnk_fopl_from_section_contrib(COFF_SectionHeader **image_section_table, LNK_SectionContrib *sc)
{
  U64 foff = lnk_foff_from_section_contrib(image_section_table, sc);
  return foff + sc->u.size;
}

internal LNK_SectionContrib *
lnk_get_first_section_contrib(LNK_Section *sect)
{
  if (sect->contribs.chunk_count > 0) {
    if (sect->contribs.first->count > 0) {
      return sect->contribs.first->v[0];
    }
  }
  return 0;
}

internal LNK_SectionContrib *
lnk_get_last_section_contrib(LNK_Section *sect)
{
  if (sect->contribs.chunk_count > 0) {
    if (sect->contribs.last->count > 0) {
      return sect->contribs.last->v[sect->contribs.last->count-1];
    }
  }
  return 0;
}

internal U64
lnk_get_section_contrib_size(LNK_Section *sect)
{
  LNK_SectionContrib *first_sc = lnk_get_first_section_contrib(sect);
  LNK_SectionContrib *last_sc = lnk_get_last_section_contrib(sect);
  U64 size = (last_sc->u.off - first_sc->u.off) + last_sc->u.size;
  return size;
}

internal U64
lnk_get_first_section_contrib_voff(COFF_SectionHeader **image_section_table, LNK_Section *sect)
{
  LNK_SectionContrib *sc = lnk_get_first_section_contrib(sect);
  return lnk_voff_from_section_contrib(image_section_table, sc);
}

internal LNK_SectionTable *
lnk_section_table_alloc(void)
{
  ProfBeginFunction();
  Arena *arena = arena_alloc();
  LNK_SectionTable *sectab = push_array(arena, LNK_SectionTable, 1);
  sectab->arena            = arena;
  sectab->sect_ht          = hash_table_init(arena, 256);
  ProfEnd();
  return sectab;
}

internal void
lnk_section_table_release(LNK_SectionTable **st_ptr)
{
  ProfBeginFunction();
  LNK_SectionTable *sectab = *st_ptr;
  arena_release(sectab->arena);
  *st_ptr = 0;
  ProfEnd();
}

internal String8
lnk_make_name_with_flags(Arena *arena, String8 name, COFF_SectionFlags flags)
{
  Temp scratch = scratch_begin(&arena, 1);
  String8List l = {0};
  str8_list_push(scratch.arena, &l, name);
  str8_list_push(scratch.arena, &l, str8_struct(&flags));
  String8 name_with_flags = str8_list_join(arena, &l, 0);
  scratch_end(scratch);
  return name_with_flags;
}

internal LNK_Section *
lnk_section_table_push(LNK_SectionTable *sectab, String8 name, COFF_SectionFlags flags)
{
  ProfBeginFunction();

  LNK_SectionNode *sect_node = push_array(sectab->arena, LNK_SectionNode, 1);
  LNK_Section     *sect      = &sect_node->data;
  sect->id           = sectab->id_max++;
  sect->name         = push_str8_copy(sectab->arena, name);
  sect->flags        = flags;
  sect->has_layout   = 1;

  LNK_SectionList *sect_list = &sectab->list;
  SLLQueuePush(sect_list->first, sect_list->last, sect_node);
  sect_list->count += 1;

  String8 name_with_flags = lnk_make_name_with_flags(sectab->arena, name, flags);
  hash_table_push_string_raw(sectab->arena, sectab->sect_ht, name_with_flags, sect);

  ProfEnd();
  return sect;
}

internal LNK_SectionNode *
lnk_section_table_remove(LNK_SectionTable *sectab, String8 name)
{
  ProfBeginFunction();
  
  // find node
  LNK_SectionNode *node;
  for (node = sectab->list.first; node != 0; node = node->next) {
    if (str8_match(node->data.name, name, 0)) {
      break;
    }
  }

  // remove node
  {
    LNK_SectionList *list = &sectab->list;
    if (list->count > 0) {
      if (list->first == node) {
        list->first = list->first->next;
        list->count -= 1;

        if (list->last == node) {
          list->last = 0;
        }
      } else {
        for (LNK_SectionNode *curr = list->first, *prev = 0; curr != 0; prev = curr, curr = curr->next) {
          if (curr == node) {
            prev->next = curr->next;
            list->count -= 1;

            if (list->last == curr) {
              list->last = prev;
            }

            break;
          }
        }
      }
    }
  }

  ProfEnd();
  return node;
}

internal LNK_Section *
lnk_section_table_search(LNK_SectionTable *sectab, String8 full_or_partial_name, COFF_SectionFlags flags)
{
  Temp scratch = scratch_begin(0,0);

  String8 name = {0};
  String8 postfix = {0};
  coff_parse_section_name(full_or_partial_name, &name, &postfix);

  String8 name_with_flags = lnk_make_name_with_flags(scratch.arena, name, flags);
  LNK_Section *section= 0;
  hash_table_search_string_raw(sectab->sect_ht, name_with_flags, &section);

  scratch_end(scratch);
  return section;
}

internal LNK_SectionArray
lnk_section_table_search_many(Arena *arena, LNK_SectionTable *sectab, String8 full_or_partial_name)
{
  String8 name = {0};
  String8 postfix = {0};
  coff_parse_section_name(full_or_partial_name, &name, &postfix);

  U64 match_count = 0;
  for (LNK_SectionNode *sect_n = sectab->list.first; sect_n != 0; sect_n = sect_n->next) {
    if (str8_match(sect_n->data.name, name, 0)) {
      match_count += 1;
    }
  }

  LNK_SectionArray result = {0};

  if (match_count > 0) {
    result.count = 0;
    result.v = push_array(arena, LNK_Section *, match_count);

    for (LNK_SectionNode *sect_n = sectab->list.first; sect_n != 0; sect_n = sect_n->next) {
      if (str8_match(sect_n->data.name, name, 0)) {
        result.v[result.count++] = &sect_n->data;
      }
    }
  }

  return result;
}

internal void
lnk_section_table_merge(LNK_SectionTable *sectab, LNK_MergeDirectiveList merge_list)
{
  ProfBeginFunction();
  Temp scratch = scratch_begin(0, 0);
  
  LNK_Section **src_dst = push_array(scratch.arena, LNK_Section *, sectab->id_max);
  for (LNK_MergeDirectiveNode *merge_node = merge_list.first; merge_node != 0; merge_node = merge_node->next) {
    LNK_MergeDirective *merge = &merge_node->data;

    // guard against illegal merges
    {
      local_persist String8 illegal_merge_sections[] = {
        str8_lit_comp(".rsrc"),
        str8_lit_comp(".reloc"),
      };
      for (U64 i = 0; i < ArrayCount(illegal_merge_sections); i += 1) {
        if (str8_match(merge->src, illegal_merge_sections[i], 0)) {
          lnk_error(LNK_Error_IllegalSectionMerge, "illegal to merge %S with %S", illegal_merge_sections[i], merge->dst);
        }
        if (str8_match(merge->dst, illegal_merge_sections[i], 0)) {
          lnk_error(LNK_Error_IllegalSectionMerge, "illegal to merge %S with %S", merge->src, illegal_merge_sections[i]);
        }
      }
    }

    // guard against circular merges
    {
      if (str8_match(merge_node->data.dst, merge_node->data.src, 0)) {
        lnk_error(LNK_Error_CircularMerge, "detected circular /MERGE:%S=%S", merge_node->data.src, merge_node->data.dst);
      }
      for (LNK_SectionNode *sect_n = sectab->merge_list.first; sect_n != 0; sect_n = sect_n->next) {
        if (str8_match(sect_n->data.name, merge_node->data.dst, 0) ||
            str8_match(sect_n->data.name, merge_node->data.src, 0)) {
          lnk_error(LNK_Error_CircularMerge, "detected circular /MERGE:%S=%S", merge_node->data.src, merge_node->data.dst);
        }
      }
    }
    
    // are we trying to merge section that was already merged?
    LNK_Section *merge_sect = 0;
    hash_table_search_string_raw(sectab->sect_ht, merge->src, &merge_sect);
    if (merge_sect && merge_sect->is_merged) {
      LNK_Section *dst = src_dst[merge_sect->id];
      B32 is_ambiguous_merge = !str8_match(dst->name, merge->dst, 0);
      if (is_ambiguous_merge) {
        lnk_error(LNK_Warning_AmbiguousMerge, "Detected ambiguous section merge:");
        lnk_supplement_error("%S => %S (Merged)", merge_sect->name, dst->name);
        lnk_supplement_error("%S => %S", merge_sect->name, merge->dst);
      }
      continue;
    }
    
    // find source seciton
    LNK_SectionArray src_matches = lnk_section_table_search_many(scratch.arena, sectab, merge->src);
    if (src_matches.count == 0) {
      continue;
    }

    LNK_Section *dst;
    {
      LNK_SectionArray dst_matches = lnk_section_table_search_many(scratch.arena, sectab, merge->dst);

      if (dst_matches.count > 1) {
        lnk_error(LNK_Warning_AmbiguousMerge, "unable to merge %S=%S, too many dest sections (%llu)", merge->src, merge->dst, dst_matches.count);
        continue;
      }

      // handle case where destination section doesn't exist
      if (dst_matches.count == 0) {
        dst = lnk_section_table_push(sectab, merge->dst, src_matches.v[0]->flags);
      } else {
        dst = dst_matches.v[0];
      }
    }

    for (U64 src_idx = 0; src_idx < src_matches.count; src_idx += 1) {
      LNK_Section *src = src_matches.v[src_idx];

      // update map
      src_dst[src->id] = dst;

      // merge section with destination
      lnk_section_contrib_chunk_list_concat_in_place(&dst->contribs, &src->contribs);
      src->is_merged = 1;
      src->merge_id = dst->id;

      // remove from output section list
      LNK_SectionNode *merge_node = lnk_section_table_remove(sectab, src->name);

      // move node to the merge list
      SLLQueuePush(sectab->merge_list.first, sectab->merge_list.last, merge_node);
      sectab->merge_list.count += 1;
    }
  }
  scratch_end(scratch);
  ProfEnd();
}

internal LNK_SectionArray
lnk_section_table_get_output_sections(Arena *arena, LNK_SectionTable *sectab)
{
  LNK_SectionArray result = {0};
  result.count            = 0;
  result.v                = push_array(arena, LNK_Section *, sectab->list.count);

  for (LNK_SectionNode *sect_node = sectab->list.first; sect_node != 0; sect_node = sect_node->next) {
    if (sect_node->data.has_layout) {
      Assert(result.count < sectab->list.count);
      result.v[result.count] = &sect_node->data;
      result.count += 1;
    }
  }

  U64 unused_entry_count = sectab->list.count - result.count;
  arena_pop(arena, unused_entry_count * sizeof(result.v[0]));

  return result;
}

internal void
lnk_finalize_section_layout(LNK_SectionTable *sectab, LNK_Section *sect, U64 file_align)
{
  U64 cursor = 0;
  for (LNK_SectionContribChunk *sc_chunk = sect->contribs.first; sc_chunk != 0; sc_chunk = sc_chunk->next) {
    for (U64 sc_idx = 0; sc_idx < sc_chunk->count; sc_idx += 1) {
      LNK_SectionContrib *sc = sc_chunk->v[sc_idx];

      cursor = AlignPow2(cursor, sc->align);

      // store section contribution start offset
      U64 sc_off = cursor;

      // compute contrib size
      U64 sc_size = 0;
      for (String8Node *data_n = sc->data_list; data_n != 0; data_n = data_n->next) {
        sc_size += data_n->string.size;
      }

      cursor += sc_size;

      // assign offset and size
      sc->u.off  = sc_off;
      sc->u.size = sc_size;
    }
  }

  if (~sect->flags & COFF_SectionFlag_CntUninitializedData) {
    sect->fsize = AlignPow2(cursor, file_align);
  }
  sect->vsize = cursor;
}


internal void
lnk_assign_section_index(LNK_Section *sect, U64 sect_idx)
{
  sect->sect_idx = sect_idx;

  // assign section indices to contribs
  for (LNK_SectionContribChunk *sc_chunk = sect->contribs.first; sc_chunk != 0; sc_chunk = sc_chunk->next) {
    for (U64 sc_idx = 0; sc_idx < sc_chunk->count; sc_idx += 1) {
      sc_chunk->v[sc_idx]->u.sect_idx = sect_idx;
    }
  }
}

internal void
lnk_assign_section_virtual_space(LNK_Section *sect, U64 sect_align, U64 *voff_cursor)
{
  sect->voff    = *voff_cursor;
  *voff_cursor += sect->vsize;
  *voff_cursor  = AlignPow2(*voff_cursor, sect_align);
}

internal void
lnk_assign_section_file_space(LNK_Section *sect, U64 *foff_cursor)
{
  if (~sect->flags & COFF_SectionFlag_CntUninitializedData) {
    sect->foff    = *foff_cursor;
    *foff_cursor += sect->fsize;
  }
}

internal LNK_Section *
lnk_finalized_section_from_id(LNK_SectionTable *sectab, U64 id)
{
  for (LNK_SectionNode *sect_n = sectab->list.first; sect_n != 0; sect_n = sect_n->next) {
    if (sect_n->data.id == id) {
      return &sect_n->data;
    }
  }

  for (LNK_SectionNode *sect_n = sectab->merge_list.first; sect_n != 0; sect_n = sect_n->next) {
    if (sect_n->data.id == id) {
      return lnk_finalized_section_from_id(sectab, sect_n->data.merge_id);
    }
  }

  return 0;
}


