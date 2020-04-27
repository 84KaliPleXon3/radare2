/* radare - LGPL - Copyright 2008-2020 - nibble, pancake */

#include <r_anal.h>
#include <r_core.h>

static bool item_matches_filter(RAnalMetaItem *item, RAnalMetaType type, R_NULLABLE const RSpace *space) {
	return (type == R_META_TYPE_ANY || item->type == type)
		   && (!space || item->space == space);
}

typedef struct {
	RAnalMetaType type;
	const RSpace *space;

	RIntervalNode *node;
} FindCtx;

static bool find_node_cb(RIntervalNode *node, void *user) {
	FindCtx *ctx = user;
	if (item_matches_filter (node->data, ctx->type, ctx->space)) {
		ctx->node = node;
		return false;
	}
	return true;
}

static RIntervalNode *find_node_at(RAnal *anal, RAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	r_interval_tree_all_at (&anal->meta, addr, find_node_cb, &ctx);
	return ctx.node;
}

static RIntervalNode *find_node_in(RAnal *anal, RAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	r_interval_tree_all_in (&anal->meta, addr, true, find_node_cb, &ctx);
	return ctx.node;
}

typedef struct {
	RAnalMetaType type;
	const RSpace *space;

	RPVector/*RIntervalNode*/ *result;
} CollectCtx;

static bool collect_nodes_cb(RIntervalNode *node, void *user) {
	CollectCtx *ctx = user;
	if (item_matches_filter (node->data, ctx->type, ctx->space)) {
		r_pvector_push (ctx->result, node);
	}
	return true;
}

static RPVector *collect_nodes_in(RAnal *anal, RAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = r_pvector_new (NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	r_interval_tree_all_in (&anal->meta, addr, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RPVector *collect_nodes_intersect(RAnal *anal, RAnalMetaType type, R_NULLABLE const RSpace *space, ut64 start, ut64 end) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = r_pvector_new (NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	r_interval_tree_all_intersect (&anal->meta, start, end, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

R_API bool r_meta_set_string(RAnal *a, RAnalMetaType type, ut64 addr, const char *s) {
	RSpace *space = r_spaces_current (&a->meta_spaces);
	RIntervalNode *node = find_node_at (a, type, space, addr);
	RAnalMetaItem *item = node ? node->data : R_NEW0 (RAnalMetaItem);
	if (!item) {
		return false;
	}
	item->type = type;
	item->space = space;
	free (item->str);
	item->str = strdup (s);
	if (!item->str) {
		if (!node) { // If we just created this
			free (item);
		}
		return false;
	}
	if (!node) {
		r_interval_tree_insert (&a->meta, addr, addr, item);
	}
	return true;
}

R_API const char *r_meta_get_string(RAnal *a, RAnalMetaType type, ut64 addr) {
	RIntervalNode *node = find_node_at (a, type, r_spaces_current (&a->meta_spaces), addr);
	if (!node) {
		return NULL;
	}
	RAnalMetaItem *item = node->data;
	return item->str;
}


R_API void r_meta_del(RAnal *a, RAnalMetaType type, ut64 addr, ut64 size) {
	RPVector *victims = NULL;
	RSpace *space = r_spaces_current (&a->meta_spaces);
	if (size == UT64_MAX) {
		// delete everything
		victims = r_pvector_new (NULL);
		if (!victims) {
			return;
		}
		RBIter it;
		RAnalMetaItem *item;
		r_interval_tree_foreach (&a->meta, it, item) {
			if (item_matches_filter (item, type, space)) {
				r_pvector_push (victims, r_rbtree_iter_get (&it, RIntervalNode, node));
			}
		}
	} else {
		ut64 end = addr + size;
		if (end < addr) {
			end = UT64_MAX;
		}
		victims = collect_nodes_intersect (a, type, space, addr, end);
		if (!victims) {
			return;
		}
	}
	void **it;
	r_pvector_foreach (victims, it) {
		r_interval_tree_delete (&a->meta, *it, true);
	}
	r_pvector_free (victims);
}

R_API void r_meta_cleanup(RAnal *a, ut64 from, ut64 to) {
	r_meta_del (a, R_META_TYPE_ANY, from, (to-from));
}

static void r_meta_item_fini(RAnalMetaItem *item) {
	free (item->str);
}

R_API void r_meta_item_free(void *_item) {
	if (_item) {
		RAnalMetaItem *item = _item;
		r_meta_item_fini (item);
		free (item);
	}
}

static int meta_add(RAnal *a, RAnalMetaType type, int subtype, ut64 from, ut64 to, const char *str) {
	if (to < from) {
		return false;
	}
	RSpace *space = r_spaces_current (&a->meta_spaces);
	RAnalMetaItem *item = R_NEW0 (RAnalMetaItem);
	if (!item) {
		return false;
	}
	item->type = type;
	item->subtype = subtype;
	item->space = space;
	free (item->str);
	item->str = strdup (str);
	if (!item->str) {
		free (item);
		return false;
	}
	r_interval_tree_insert (&a->meta, from, to, item);
	return true;
}

R_API int r_meta_add(RAnal *a, int type, ut64 from, ut64 to, const char *str) {
	return meta_add (a, type, 0, from, to, str);
}

R_API int r_meta_add_with_subtype(RAnal *a, int type, int subtype, ut64 from, ut64 to, const char *str) {
	return meta_add (a, type, subtype, from, to, str);
}

// TODO should be named get imho
R_API RAnalMetaItem *r_meta_find(RAnal *a, ut64 at, int type) {
	RIntervalNode *node = find_node_at (a, type, r_spaces_current (&a->meta_spaces), at);
	return node ? node->data : NULL;
}

R_API RAnalMetaItem *r_meta_find_in(RAnal *a, ut64 at, int type) {
	RIntervalNode *node = find_node_in (a, type, r_spaces_current (&a->meta_spaces), at);
	return node ? node->data : NULL;
}

R_API RPVector *r_meta_find_list_in(RAnal *a, ut64 at) {
	return collect_nodes_in (a, R_META_TYPE_ANY, r_spaces_current (&a->meta_spaces), at);
}

R_API const char *r_meta_type_to_string(int type) {
	// XXX: use type as '%c'
	switch (type) {
	case R_META_TYPE_DATA: return "Cd";
	case R_META_TYPE_CODE: return "Cc";
	case R_META_TYPE_STRING: return "Cs";
	case R_META_TYPE_FORMAT: return "Cf";
	case R_META_TYPE_MAGIC: return "Cm";
	case R_META_TYPE_HIDE: return "Ch";
	case R_META_TYPE_COMMENT: return "CCu";
	case R_META_TYPE_RUN: return "Cr"; // not in C? help
	case R_META_TYPE_HIGHLIGHT: return "ecHi"; // not in C?
	case R_META_TYPE_VARTYPE: return "Ct";
	}
	return "# unknown meta # ";
}

R_API void r_meta_print(RAnal *a, RAnalMetaItem *d, ut64 start, ut64 end, int rad, PJ *pj, bool show_full) {
	r_return_if_fail (!(rad == 'j' && !pj)); // rad == 'j' => pj != NULL
	ut64 size = end - start;
	char *pstr, *str, *base64_str;
	RCore *core = a->coreb.core;
	bool esc_bslash = core ? core->print->esc_bslash : false;
	if (r_spaces_current (&a->meta_spaces) &&
	    r_spaces_current (&a->meta_spaces) != d->space) {
		return;
	}
	if (d->type == 's') {
		if (d->subtype == R_STRING_ENC_UTF8) {
			str = r_str_escape_utf8 (d->str, false, esc_bslash);
		} else {
			if (!d->subtype) {  /* temporary legacy workaround */
				esc_bslash = false;
			}
			str = r_str_escape_latin1 (d->str, false, esc_bslash, false);
		}
	} else {
		str = r_str_escape (d->str);
	}
	if (str || d->type == 'd') {
		if (d->type=='s' && !*str) {
			free (str);
			return;
		}
		if (!str) {
			pstr = "";
		} else if (d->type == 'f') {
			pstr = str;
		} else if (d->type == 's') {
			pstr = str;
		} else if (d->type == 't') {
			// Sanitize (don't escape) Ct comments so we can see "char *", etc.
			free (str);
			str = strdup (d->str);
			r_str_sanitize (str);
			pstr = str;
		} else if (d->type != 'C') {
			r_name_filter (str, 0);
			pstr = str;
		} else {
			pstr = d->str;
		}
//		r_str_sanitize (str);
		switch (rad) {
		case 'j':
			pj_o (pj);
			pj_kn (pj, "offset", start);
			pj_ks (pj, "type", r_meta_type_to_string (d->type));

			if (d->type == 'H') {
				pj_k (pj, "color");
				ut8 r = 0, g = 0, b = 0, A = 0;
				const char *esc = strchr (d->str, '\x1b');
				if (esc) {
					r_cons_rgb_parse (esc, &r, &g, &b, &A);
					char *rgb_str = r_cons_rgb_tostring (r, g, b);
					base64_str = r_base64_encode_dyn (rgb_str, -1);
					if (d->type == 's' && base64_str) {
						pj_s (pj, base64_str);
						free (base64_str);
					} else {
						pj_s (pj, rgb_str);
					}
					free (rgb_str);
				} else {
					pj_s (pj, str);
				}
			} else {
				pj_k (pj, "name");
				if (d->type == 's' && (base64_str = r_base64_encode_dyn (d->str, -1))) {
					pj_s (pj, base64_str);
				} else {
					pj_s (pj, str);
				}
			}
			if (d->type == 'd') {
				pj_kn (pj, "size", size);
			} else if (d->type == 's') {
				const char *enc;
				switch (d->subtype) {
				case R_STRING_ENC_UTF8:
					enc = "utf8";
					break;
				case 0:  /* temporary legacy encoding */
					enc = "iz";
					break;
				default:
					enc = "latin1";
				}
				pj_ks (pj, "enc", enc);
				pj_kb (pj, "ascii", r_str_is_ascii (d->str));
			}

			pj_end (pj);
			break;
		case 0:
		case 1:
		case '*':
		default:
			switch (d->type) {
			case 'a': //var and arg comments
			case 'v':
			case 'e':
				//XXX I think they do not belong to here
				break;
			case 'C':
				{
				const char *type = r_meta_type_to_string (d->type);
				char *s = sdb_encode ((const ut8*)pstr, -1);
				if (!s) {
					s = strdup (pstr);
				}
				if (rad) {
					if (!strcmp (type, "CCu")) {
						a->cb_printf ("%s base64:%s @ 0x%08"PFMT64x"\n",
							type, s, start);
					} else {
						a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
							type, pstr, start);
					}
				} else {
					if (!strcmp (type, "CCu")) {
						char *mys = r_str_escape (pstr);
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								start, type, mys);
						free (mys);
					} else {
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								start, type, pstr);
					}
				}
				free (s);
				}
				break;
			case 's': /* string */
				if (rad) {
					char cmd[] = "Cs#";
					switch (d->subtype) {
					case 'a':
					case '8':
						cmd[2] = d->subtype;
						break;
					default:
						cmd[2] = 0;
					}
					a->cb_printf ("%s %"PFMT64u" @ 0x%08"PFMT64x" # %s\n",
							cmd, size, start, pstr);
				} else {
					const char *enc;
					switch (d->subtype) {
					case '8':
						enc = "utf8";
						break;
					default:
						enc = r_str_is_ascii (d->str) ? "ascii" : "latin1";
					}
					if (show_full) {
						a->cb_printf ("0x%08"PFMT64x" %s[%"PFMT64u"] \"%s\"\n",
						              start, enc, size, pstr);
					} else {
						a->cb_printf ("%s[%"PFMT64u"] \"%s\"\n",
						              enc, size, pstr);
					}
				}
				break;
			case 'h': /* hidden */
			case 'd': /* data */
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" @ 0x%08"PFMT64x"\n",
							r_meta_type_to_string (d->type),
							size, start);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'h' ? "hidden" : "data";
						a->cb_printf ("0x%08" PFMT64x " %s %s %"PFMT64u"\n",
						              start, dtype,
						              r_meta_type_to_string (d->type), size);
					} else {
						a->cb_printf ("%"PFMT64u"\n", size);
					}
				}
				break;
			case 'm': /* magic */
			case 'f': /* formatted */
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" %s @ 0x%08"PFMT64x"\n",
							r_meta_type_to_string (d->type),
							size, pstr, start);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'm' ? "magic" : "format";
						a->cb_printf ("0x%08" PFMT64x " %s %"PFMT64u" %s\n",
						              start, dtype, size, pstr);
					} else {
						a->cb_printf ("%"PFMT64u" %s\n", size, pstr);
					}
				}
				break;
			case 't': /* vartype */
				if (rad) {
					a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
						r_meta_type_to_string (d->type), pstr, start);
				} else {
					a->cb_printf ("0x%08"PFMT64x" %s\n", start, pstr);
				}
				break;
			case 'H':
				{
					ut8 r = 0, g = 0, b = 0, A = 0;
					const char *esc = strchr (d->str, '\x1b');
					r_cons_rgb_parse (esc, &r, &g, &b, &A);
					a->cb_printf ("%s rgb:%02x%02x%02x @ 0x%08"PFMT64x"\n",
						r_meta_type_to_string (d->type), r, g, b, start);
					// TODO: d->size
				}
				break;
			default:
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" 0x%08"PFMT64x" # %s\n",
						r_meta_type_to_string (d->type),
						size, start, pstr);
				} else {
					// TODO: use b64 here
					a->cb_printf ("0x%08"PFMT64x" array[%"PFMT64u"] %s %s\n",
						start, size,
						r_meta_type_to_string (d->type), pstr);
				}
				break;
			}
			break;
		}
		if (str) {
			free (str);
		}
	}
}

R_API void r_meta_list_offset(RAnal *a, ut64 addr) {
	const int types[] = {
		R_META_TYPE_VARTYPE,
		R_META_TYPE_HIGHLIGHT,
		R_META_TYPE_RUN,
		R_META_TYPE_COMMENT,
		R_META_TYPE_HIDE,
		R_META_TYPE_MAGIC,
		R_META_TYPE_FORMAT,
		R_META_TYPE_STRING,
		R_META_TYPE_CODE,
		R_META_TYPE_DATA,
	};

	char key[100];
	int i;

	for (i = 0; i < sizeof (types) / sizeof (types[0]); i ++) {

		snprintf (key, sizeof (key)-1, "meta.%c.0x%"PFMT64x, types[i], addr);
		const char *k = sdb_const_get (DB, key, 0);
		if (!k) {
			continue;
		}

		RAnalMetaUserItem ui = { a };

		meta_print_item ((void *)&ui, key, k);
	}
}


R_API int r_meta_list_cb(RAnal *a, int type, int rad, SdbForeachCallback cb, void *user, ut64 addr) {
	PJ *pj = NULL;
	if (rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return 0;
		}
		pj_a (pj);
	}

	RAnalMetaUserItem ui = { a, type, rad, cb, user, 0, NULL, pj };

	if (addr != UT64_MAX) {
		ui.fcn = r_anal_get_fcn_in (a, addr, 0);
		if (!ui.fcn) {
			goto beach;
		}
	}

	SdbList *ls = sdb_foreach_list (DB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		if (type == R_META_TYPE_ANY || (strlen (sdbkv_key (kv)) > 5 && sdbkv_key (kv)[5] == type)) {
			if (cb) {
				cb ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			} else {
				meta_print_item ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			}
		}
	}
	ls_free (ls);

beach:
	if (pj) {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	return ui.count;
}

R_API int r_meta_list(RAnal *a, int type, int rad) {
	return r_meta_list_cb (a, type, rad, NULL, NULL, UT64_MAX);
}

R_API int r_meta_list_at(RAnal *a, int type, int rad, ut64 addr) {
	return r_meta_list_cb (a, type, rad, NULL, NULL, addr);
}

static int meta_enumerate_cb(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RList *list = ui->user;
	RAnalMetaItem *it = R_NEW0 (RAnalMetaItem);
	if (!it) {
		return 0;
	}
	if (!meta_deserialize (ui->anal, it, k, v)) {
		free (it);
		goto beach;
	}
	if (!it->str) {
		free (it);
		goto beach;
	}
	r_list_append (list, it);
beach:
	return 1;
}

R_API RList *r_meta_enumerate(RAnal *a, int type) {
	RList *list = r_list_newf (r_meta_item_free);
	r_meta_list_cb (a, type, 0, meta_enumerate_cb, list, UT64_MAX);
	return list;
}

static int meta_unset_cb(void *user, const char *k, const char *v) {
	char nk[128], nv[4096];
	RAnalMetaUserItem *ui = user;
	RAnal *a = ui->anal;
	RAnalMetaItem it = {0};
	if (!strstr (k, ".0x")) {
		return 1;
	}
	meta_deserialize (ui->anal, &it, k, v);
	if (it.space && it.space == ui->user) {
		it.space = NULL;
		meta_serialize (&it, nk, sizeof (nk), nv, sizeof (nv));
		sdb_set (DB, nk, nv, 0);
	}
	return 1;
}

R_API void r_meta_space_unset_for(RAnal *a, const RSpace *space) {
	RAnalMetaUserItem ui = { .anal = a, .user = (void *)space };
	r_meta_list_cb (a, R_META_TYPE_ANY, 0, meta_unset_cb, &ui, UT64_MAX);
}

typedef struct {
	int count;
	int index;
	const RSpace *ctx;
} myMetaUser;

static int meta_count_cb(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	myMetaUser *mu = ui->user;
	RAnalMetaItem it = {0};
	if (!strstr (k, ".0x")) {
		return 1;
	}
	meta_deserialize (ui->anal, &it, k, v);
	if (mu && it.space == mu->ctx) {
		mu->count++;
	}
	r_meta_item_fini (&it);
	return 1;
}

static int get_meta_size(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RAnalMetaItem it;
	if (!meta_deserialize (ui->anal, &it, k, v)) {
		return -1;
	}
	if (ui->fcn && !r_anal_function_contains (ui->fcn, it.from)) {
		goto beach;
	}
	if (!it.str) {
		it.str = strdup (""); // don't break in free
		if (!it.str) {
			goto beach;
		}
	}
	return it.size;
beach:
	free (it.str);
	return -1;
}

R_API int r_meta_get_size(RAnal *a, int type) {
	RAnalMetaUserItem ui = { a, type, 0, NULL, NULL, 0, NULL };
	SdbList *ls = sdb_foreach_list (DB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	int tot_size = 0;
	int meta_size;
	ls_foreach (ls, lsi, kv) {
		if ((strlen (sdbkv_key (kv)) > 5 && sdbkv_key (kv)[5] == type)) {
			meta_size = get_meta_size ((void *)&ui, sdbkv_key (kv), sdbkv_value (kv));
			tot_size += meta_size > -1 ? meta_size : 0;
		}
	}
	ls_free (ls);
	return tot_size;
}


R_API int r_meta_space_count_for(RAnal *a, const RSpace *space) {
	myMetaUser mu = { .ctx = space };
	r_meta_list_cb (a, R_META_TYPE_ANY, 0, meta_count_cb, &mu, UT64_MAX);
	return mu.count;
}

R_API void r_meta_set_data_at(RAnal *a, ut64 addr, ut64 wordsz) {
	char val[0x10];
	if (snprintf (val, sizeof (val), "%"PFMT64u, wordsz) < 1) {
		return;
	}
	r_meta_add (a, R_META_TYPE_DATA, addr, addr + wordsz, val);
}
