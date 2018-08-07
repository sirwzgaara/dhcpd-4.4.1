
#ifdef _cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "dhcp.h"

#define OPTION82_SUBOPTION_CODE_SIZE 	(1)
#define OPTION82_SUBOPTION_LENGTH_SIZE  (1)
#define CM_MAC_LENGTH		(6)

static LDAP * ld = NULL;

enum OPTION82_SUBOPTION
{
	AGNET_CIRCUIT_ID = 1,
	AGENT_REMOTE_ID = 2,
	LINK_SELECTION = 5,
	VENDOR_SPECIFIC_INFORMATION = 9
};

struct cm_buffer
{
	int refcnt;
	unsigned char data[0];
};

struct ldap_server_info
{
	unsigned char addr[4];
	int port;
	char *root_dn;
	char *find_dc;
	char *pwd;
};

struct class_map
{
	char * class_key;
	char * class_value;
};

struct class_mapper
{
	int number;
	struct class_map * class_map;
	char * default_value;
};

struct ldap_server_info ldap_server_info;
struct class_mapper classmapper;

#define CACHE_CONTAINER_SIZE 			(1 << 14)
#define CACHE_CONTAINER_SIZEMASK		((1 << 14) - 1)
#define CACHE_TRESHOLD_DEFAULT			(1 << 14)
#define CACHE_MAX_DELCOUNT				(64)
#define CACHE_ESCAPED_TIME				(30)

int cache_threshold = CACHE_TRESHOLD_DEFAULT;

#define HASH_INDEX_INVALID              (-1)

struct dict
{
	const char * key;
	struct cm_buffer * class_value;
	char keycache[16];
	unsigned time;
};

struct cache_container
{
	int count;
	int hashsize;
	int hashsizemask;
	unsigned (*hash_compute)(const char *, unsigned);
	void (*hash_add)(struct cm_buffer *, struct cm_buffer *);
	void (*hash_find)(struct cm_buffer *, struct cm_buffer *);
	void (*hash_delete)(struct cm_buffer *);
	pair * hash_table;
};

static inline unsigned get_code(unsigned char * buffer)
{
	return buffer[0];
}

static inline unsigned get_length(unsigned char * buffer)
{
	return buffer[0];
}

static inline int cm_buffer_reference
(
	struct cm_buffer ** ptr,
	struct cm_buffer * bp,
	const char * file,
	int line
)
{
	if (!ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}
	else if (*ptr)
	{
		log_error("%s(%d): non-null pointer", file, line);
		*ptr = NULL;
	}
	*ptr = bp;
	bp->refcnt++;

	return 1;

}

static inline int cm_buffer_dereference
(
	struct cm_buffer **ptr,
	const char * file,
	int line
)
{
	if (!ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}
	else if (!*ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}

	(*ptr)->refcnt--;
	if (0 == (*ptr)->refcnt)
	{
		free(*ptr);
	}
	else if (*(ptr)->refent < 0)
	{
		log_error("%s(%d): negative refcnt!", file, line);
		return 0;
	}

	return 1;
}

static inline int cm_buffer_allocate
(
	struct cm_buffer ** ptr,
	unsigned len,
	const char * file,
	int line
)
{
	struct cm_buffer * bp = NULL;
	bp = colloc(1, sizeof(struct cm_buffer) + len);
	if (!bp)
	{
		log_error("%s(%d): no enough memeory", file, line);
		return 0;
	}

	bp->refent = 0;
	return cm_buffer_reference(ptr, bp, file, line);
}

/* there are two kinds of options, one is from raw packet, the other is created by
software implicitly which cannot use packet buffer obviously, so as different way
to deal with it */
static inline int implicit_option_cache_reference
(
	struct option_cache ** ptr,
	struct option_cache * bp,
	const char * file,
	int line
)
{
	if (!ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}
	else if (*ptr)
	{
		log_error("%s(%d): non-null pointer", file, line);
		*ptr = NULL;
	}
	*ptr = bp;
	bp->refcnt++;

	return 1;
}

static inline int implicit_option_cache_dereference
(
	struct option_cache ** ptr,
	const char * file,
	int line
)
{
	if (!ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}
	else if (!*ptr)
	{
		log_error("%s(%d): null pointer", file, line);
		return 0;
	}

	(*ptr)->refcnt--;
	if (0 == (*ptr)->refcnt)
	{
		if ((*ptr)->data.data)
			free((*ptr)->data.data);
		free(ptr);
	}
	else if (0 < (*ptr)->refcnt)
	{
		log_error("%s(%d): negative refcnt!", file, line);
		return 0;
	}

	return 1;
}

static inline int implicit_option_cache_allocate
(
	struct option_cache **ptr,
	const char * file,
	int line
)
{
	struct option_cache * rval;
	rval = colloc(1, sizeof(struct option_cache));
	if (!rval)
		return 0;
	return implicit_option_cache_reference(ptr, rval, file, line);
}

static inline char * data_allocate(int length)
{
	return (char *)colloc(1, length);
}

static inline void data_free(char * data)
{
	if (!data)
		free(data);
}

int get_suboption_value
(
	data_string d,
	enum OPTION82_SUBOPTION suboption,
	void * value
)
{
	unsigned offset, code, length;
	unsigned char * buffer;

	buffer = d.data;
	if (!buffer)
	{
		log_error("no buffer for suboption");
		return 0;
	}

	for (offset = 0; offset + OPTION82_SUBOPTION_CODE_SIZE <= d.len;)
	{
		code = get_code(buffer + offset);
		offset += OPTION82_SUBOPTION_CODE_SIZE;

		if (offset + OPTION82_SUBOPTION_LENGTH_SIZE > d.len)
		{
			log_error("code tag at end of buffer - missing length field");
			return 0;
		}

		length = get_length(buffer + offset);
		offset += OPTION82_SUBOPTION_LENGTH_SIZE;

		if (code == suboption)
		{
			switch (code)
			{
				case AGNET_CIRCUIT_ID:
				case LINK_SELECTION:
				case VENDOR_SPECIFIC_INFORMATION:
					// TODO:
					break;
				case AGENT_REMOTE_ID:
					if (length > CM_MAC_LENGTH)
					{
						log_error("mac size overflow: %d", length);
						return 0;
					}

					cm_buffer_allocate(&(struct cm_buffer *)value, length + 1, MDL);
					memcpy(((struct cm_buffer *)value)->data, buffer + offset, length);
					((struct cm_buffer *)value)->data[length] = '\0';

					break;
				default:
					break;
			}
			return 1;
		}

		if (offset + length > d.len)
		{
			log_error("option length exceeds option buffer length");
			return 0;
		}
		offset += length;
	}

	log_info("can not find suboption value of option82");
	return 0;
}

int get_option82_suboption_value
(
	struct packet * packet,
	enum OPTION82_SUBOPTION suboption,
	void * value
)
{
	struct option_cache *oc;
	struct data_string d;
	int result = 1;

	//obtain value from option82
	oc = lookup_option(&dhcp_universe, packet->options, DHO_DHCP_AGENT_OPTIONS);
	if (!oc ||
	    !evaluate_option_cache(&d, packet, NULL, NULL,
				  packet->options, NULL,
				  &global_scope, oc, MDL))
	{
		log_info("there is no option82 in packet");
		result = 0;
		goto clean;
	}

	//obtain specific value from suboption of option82
	if (!get_suboption_value(d, suboption, value))
	{
		log_error("failed to parse cm_mac in option82");
		result = 0;
		goto clean;
	}

	clean:
	data_string_forget(&d, MDL);

	return result;
}

/* select which class to use with option60, default class is set so there must be 
a class_name for caller */
int select_class
(
	struct packet * packet,
	struct cm_buffer * class_name
)
{
	struct option_cache *oc;
	struct data_string d;
	int i, length, number;
	int result = 1;
	struct class_mapper * pmapper = &classmapper;
	char * value;

	i = number = pmapper->number;

	oc = lookup_option(&dhcp_universe, packet->options, DHO_VENDOR_CLASS_IDENTIFIER);
	if (oc &&
	    evaluate_option_cache(&d, packet, NULL, NULL,
				  packet->options, NULL,
				  &global_scope, oc, MDL))
	{
		for (i = 0; i < number; i++)
		{
			length = strlen(pmapper->class_map[i]->class_key);
			if (!memcmp(pmapper->class_map[i]->class_key, d.data, length))
			{
				break;
			}
		}
	}

	//use default value
	if (number == i)
	{
		length = strlen(pmapper->default_value);
		value = pmapper->default_value;
	}
	else
	{
		length = strlen(pmapper->class_map[i]->class_value);
		value = pmapper->class_map[i]->class_value;
	}

	cm_buffer_allocate(&class_name, length + 1, MDL);
	if (!class_name)
	{
		log_error("no enough memory");
		result = 0;
		goto clean;
	}

	memcpy(class_name->data, value, length + 1);

	clean:
	data_string_forget(&d, MDL);

	return;
}

/* since at this point we have already parsed option82, there must be a hashtable */
int create_implicit_option
(
	struct packet * packet,
	struct universe universe,
	struct cm_buffer * class_value,
	unsigned code,
)
{
	struct option_cache * op = NULL;
	struct option * option = NULL;
	int result = 1;

	option_code_hash_lookup(&option, universe->code_hash, &code, 0, MDL);
	if (!option)
	{
	    log_error("can not find option %d", code);
	    result = 0;
		goto clean;
	}

	op = lookup_option(universe, packet->options, code);
	if (!op)
	{
        //create option_cache
        implicit_option_cache_allocate(&op, MDL);
        option_reference(&op->option, option, MDL);
        op->data.len  = strlen(class_value->data);
        op->data.data = data_allocate(op->data.len);
		if (NULL == op->data.data)
		{
			log_error("no enough memory for op->data.data");
			result = 0;
			goto clean;
		}

        memcpy(op->data.data, class_value->data, op->data.len);

		//add option_cache to hash
		save_option(universe, options, op);
	}
	else
	{
        /* already parsed option with code, it's a conflict, should not happen,
			if it occurs, do not set result flag */
        log_error("already parse option %d", code);
		goto clean;
	}

	clean:
	if (option)
		option_dereference(&option, MDL);
	if (op)
		option_cache_dereference(&op, MDL);

	return result;
}

void destory_option
(
	struct packet * packet,
	struct universe universe,
	struct cm_buffer * class_name,
	unsigned code,
)
{
	struct option_cache * op = NULL;

	while (op = lookup_option(universe, packet->options, code))
	{
		delete_option(universe, packet->options, code);
		data_free(op->data.data);
		option_cache_dereference(&op, MDL);
	}
}

int connect_ldap()
{
	int rc, version;
	char buf[128] = {0};
	struct ldap_server_info * pserver = &ldap_server_info;
	unsigend char * p = pserver->addr;
	int port = pserver->port;

	snprintf(buf, sizeof(buf), "ldap://%u.%u.%u.%u:%d", p[0], p[1], p[2], p[3], port);

	rc = ldap_initialize(&ld, buf);
	if (LDAP_SUCCESS != rc)
	{
		log_error("failed to initialize descriptor of ldap");
		return 0;
	}

	version = LDAP_VERSION3;
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	rc = ldap_simple_bind_s(ld, pserver->root_dn, pserver->pwd);
	if (LDAP_SUCCESS != rc)
	{
		log_error("failed to bind with ldap server, err: %s", ldap_err2string(rc));
		return 0;
	}

	return 1;
}

int get_class_from_ldap
(
	struct cm_buffer * cm_mac,
	struct cm_buffer * class_name,
	struct cm_buffer * class_value
)
{
	int rc, i, matchflag = 0;
	LDAP_Message *result, *e;
	char *a;
	BerElement *ber;
	struct berval **vals;
	char buf[128] = {0};
	int length;

	if (NULL == ld)
	{
		log_error("not bind to ldap server yet");
		return 0;
	}

	snprintf(buf, sizeof(buf), "(&(cmmac2=%s)(objectclass=*))", cm_mac->data);

	if ((rc = ldap_search_ext_s(ld, ldap_server_info.find_dc, LDAP_SCOPE_SUB, buf,
              NULL, 0, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
	{
		log_error("failed to search ldap: %s", ldap_err2string(rc));
		return 0;
	}

	e = ldap_first_entry(ld, result);
	if (!e)
	{
		log_error("failed to get first entry");
		return 0;
	}

	for (a = ldap_first_attribute(ld, e, &ber); a != NULL;
			a = ldap_next_attribute(ld, e, ber))
	{
		if ((vals = ldap_get_values_len(ld, e, a)) != NULL)
		{
			for (i = 0; vals[i] != NULL; i++)
			{
				if (!memcmp(a, class_name->data, strlen(class_name->data)))
				{
					length = vals[i]->bv_len;
					cm_buffer_allocate(&class_value, length + 1, MDL);
					memcpy(class_value->data, vals[i]->bv_val, length);
					class_value->data[length] = '\0';
					matchflag = 1;

					break;
				}
			}
			ber_bvecfree(vals);
		}
		ldap_memfree(a);
		if (matchflag)
			break;
	}
	if (ber)
		ber_free(ber, 0);
	ldap_msgfree(result);

	return 1;
}

/* refresh class_vlaue and access time within a dict */
void dict_refresh(struct dict * dict, struct cm_buffer * class_value)
{
	if (!dict || !dict->class_value)
		return;

	cm_buffer_dereference(&(dict->class_value), MDL);
	cm_buffer_reference(&(dict->class_value), class_value, MDL);
	dict->time = cur_time;
}

/* destroy a dict, free memory */
void dict_destory(struct dict * dict)
{
	if (!dict)
		return;

	if (dict->key)
		free(dict->key);

	if (dict->class_value)
		cm_buffer_dereference(&(dict->class_value), MDL);

	free(dict);
}

/* obtain some keys in random, return numbers of keys obtain success */
int dict_get_some_keys
(
	unsigned int count,
	struct dict ** dict
)
{
	struct cache_container * p = &cache_container;
	unsigned int maxsteps = 10 * count;
	unsigned int stored = 0, emptylen = 0;
	pair he;

	unsigned int i = random() & p->hashsizemask;
	while (maxsteps-- && stored < count)
	{
		he = p->hash_table[i]->cdr;
		if (!he)
		{
			++emptylen;
			if (emptylen >= 5 && emptylen > count)
			{
				i = random() & p->hashsizemask;
				emptylen = 0;
			}
		}
		else
		{
			emptylen = 0;
			while (he)
			{
				dict[stored++] = (struct dict *)&(he->car);
				he = he->cdr;
				if (stored == count)
					return stored;
			}
		}
		i = (i + 1) & p->hashsizemask;
	}

	return stored;
}

void cache_try_delete(struct dict ** dict, int size)
{
	int i, j;
	struct dict * tmp;

	if (!dict)
		return;

	/* sort dict in ascending, simple insert sort, work good with little size */
	for (i = 1; i < size; i++)
	{
		tmp = dict[i];
		for (j = i; j > 0 && tmp->time < a[j - 1]->time; j--)
		{
			dict[j] = dict[j - 1];
		}
		dict[j] = tmp;
	}

	for (i = 0; i <= size / 2; i++)
	{
		if (dict[i]->key)
			cache_container.hash_delete(dict[i]->key, HASH_INDEX_INVALID);
		else
			cache_container.hash_delete(dict[i]->keycache, HASH_INDEX_INVALID);
	}
}

/* use key and len to get hashidx */
unsigned cache_hash_compute(const char * key, unsigned len)
{
	register unsigned accum = 0;
	register const unsigned char *s = key;
	int i = len;

	while (i--) 
	{
		/* Add the character in... */
		accum = (accum << 1) + *s++;

		while (accum > 65535) 
		{
			accum = (accum & 65535) + (accum >> 16);
		}
	}

	return accum;
}

/* obtain dict from hashtable */
void cache_hash_find
(
	struct cm_buffer * cm_mac,
	struct dict * value,
	int * hashidx
)
{
	pair hash;
	struct dict * dict;
	struct cache_container *p = &cache_container;

	*hashidx = p->hash_compute(cm_mac->data, strlen(cm_mac->data));
	hash = p->hash_table[*hashidx];

	for (; hash; hash = hash->cdr)
	{
		dict = (struct dict *)(hash->car);
		if (!dict)
			continue;

		if ((strlen(cm_mac->data) == strlen(dict->key)) &&
			!memcmp(cm_mac->data, dict->key, strlen(cm_mac)))
		{
			break;
		}
	}

	if (hash)
	{
		value = dict;
	}
}

/* del a element in hash table */
void cache_hash_delete
(
	struct cm_buffer * cm_mac,
	int hashidx
)
{
	unsigned hashidx;
	pair hash, now, pre;
	struct dict * dict;
	struct cache_container *p = &cache_container;

	if (HASH_INDEX_INVALID == hashidx)
		hashidx = p->hash_compute(cm_mac->data, strlen(cm_mac->data));

	hash = p->hash_table[hashidx];
	pre = now = hash;

	for (; now; pre = now, now = now->cdr)
	{
		dict = (struct dict *)(now->car);
		if ((strlen(cm_mac->data) == strlen(dict->key)) &&
			!memcmp(cm_mac->data, dict->key, strlen(cm_mac->data)))

		{
			/* free dict */
			dict_destory(dict);
			pre->cdr = now->cdr;

			if (hash == now)
				hash = NULL;

			free_pair(now);
			p->count--;

			/* there shouldn't be two same key */
			break;
		}
	}

	return;
}

void cache_freeifneed()
{
	struct cache_container * p = &cache_container;
	struct dict * dict[CACHE_MAX_DELCOUNT];
	int count = 20;

	if (p->count < CACHE_CONTAINER_SIZE)
	{
		return;
	}
	count = dict_get_some_keys(count, dict);
}


void cache_hash_add
(
	struct cm_buffer * cm_mac,
	struct cm_buffer * class_value
	int hashidx
)
{
	pair hashhead, hash_iterator, new;
	struct dict * dict;
	int keylength;
	struct cache_container * p = &cache_container;

	/* if caller provided hashidx, use it, or compute it here */
	if (HASH_INDEX_INVALID == hashidx)
		hashidx = p->hash_compute(cm_mac->data, strlen(cm_mac->data));

	hashhead = p->hash_table[hashidx];

	for (hash_iterator = hashhead; hash_iterator; hash_iterator = hash_iterator->cdr)
	{
		dict = (struct dict *)(hash->car);
		if (!dict)
			continue;

		if ((strlen(cm_mac->data) == strlen(dict->key)) &&
			!memcmp(cm_mac->data, dict->key, strlen(cm_mac)))
		{
			break;
		}
	}

	/* already has this stuff, should not happen, for insurance, refrash class_value
		and access time */
	if (hash_iterator)
	{
		dict = (struct dict *)(hash_iterator->car);
		dict_refresh(dict, class_value);
	}
	else
	{
		new = new_pair(MDL);
		if (!new)
		{
			log_fatal("no momory for new_pair");
			return;
		}

		dict = (struct dict *)(new->car);
		dict = colloc(1, sizeof(struct dict));
		if (!dict)
		{
			free(new);
			log_fatal("no enough memory for dict");
			return;
		}

		keylength = strlen(cm_mac->data) + 1;

		/* try use cache first, then malloc */
		if (keylength <= 16)
		{
			memcpy(dict->keycache, cm_mac->data, keylength);
		}
		else
		{
			dict->key = colloc(1, keylength);
			memcpy(dict->key, cm_mac->data, keylength);
		}

		cm_buffer_reference(&(dict->class_value), class_value, MDL);
		dict->time = cur_time;

		/* add new to chain */
		new->cdr = hashhead;
		hashhead = new;

		p->count++;
		cache_freeifneed();
	}

	return;
}

/* get class_value from cache, don't need class_name */
void get_class_from_cache
(
	struct cm_buffer * cm_mac,
	struct dict * dict,
	int * hashidx,
	int * overdue
)
{
	if (dict)
		dict_destory(dict);

	cache_container.hash_find(cm_mac, dict, hashidx);
	if (!dict)
		return;

	if (cur_time - dict->time > CACHE_ESCAPED_TIME)
	{
		*overdue = 1;
	}

	return;
}

void hubeiguangdian
(
	struct packet * packet
)
{
	struct cm_buffer *cm_mac = NULL;
	struct cm_buffer *class_value = NULL;
	struct cm_buffer *class_name = NULL;
	int hashidx = HASH_INDEX_INVALID;
	struct cache_container *p = &cache_container;
	struct dict * dict = NULL;
	int overdue = 0;

	/* get cm_mac from option82 */
	if (!get_option82_suboption_value(packet, AGENT_REMOTE_ID, cm_mac) || !cm_mac)
	{
		log_info("there is no cm_mac inside packet");
		goto clean;
	}

	/* obtain class_value, first look in cache, then ldap server */
	get_class_from_cache(cm_mac, dict, &hashidx, &overdue);

	/* find a dict but overdued, refresh it */
	if (dict && overdue)
	{
		/* select which class to obtain from option60 */
		select_class(packet, class_name);
		if (!class_name)
		{
			log_error("%s(%d): null pointer class_name", MDL);
			goto clean;
		}

		if (!get_class_from_ldap(cm_mac, class_name, class_value) || !class_value)
		{
			log_info("can not get class from ldap, cm_mac %s, class_name %s",
					cm_mac->data, class_name->data);
			goto clean;
		}

		dict_refresh(dict, class_value);
	}
	/* not overdued, obtain class_value from dict */
	else if (dict)
	{
		cm_buffer_reference(&class_value, dict->class_value, MDL);
	}
	/* nothing in cache, try access ldap server */
	else
	{
		select_class(packet, class_name);
		if (!class_name)
		{
			log_error("%s(%d): null pointer class_name", MDL);
			goto clean;
		}

		/* can't obtain class_value in cache, try access ldap server */
		if (!get_class_from_ldap(cm_mac, class_name, class_value) || !class_value)
		{
			log_info("can not get class from ldap, cm_mac %s, class_name %s",
					cm_mac->data, class_name->data);
			goto clean;
		}
		p->hash_add(cm_mac, class_value, hashidx);
	}

	/* create a new option */
	if (!create_implicit_option(packet, dhcp_universe, class_value, DHO_CM_CLASS))
	{
		log_info("can not create option, cm_mac %s, class_name %s",
				cm_mac->data, class_name->data);
		goto clean;
	}

	clean:
	if (cm_mac)
		cm_buffer_dereference(&cm_mac, MDL);

	if (class_value)
		cm_buffer_dereference(&class_value, MDL);

	if (class_name)
		cm_buffer_dereference(&class_name, MDL);

	return;
}


int hubeiguangdian_initialize()
{
	struct cache_container * p = &cache_container;

	memset(p, 0, sizeof(struct cache_container));

	p->hash_size 	 = CACHE_CONTAINER_SIZE;
	p->hash_sizemask = CACHE_CONTAINER_SIZEMASK;
	p->hash_compute  = cache_hash_compute;
	p->hash_add 	 = cache_hash_add;
	p->hash_find 	 = cache_hash_find;
	p->hash_delete 	 = cache_hash_delete;

	return 1;
}


#ifdef _cplusplus
}
#endif

