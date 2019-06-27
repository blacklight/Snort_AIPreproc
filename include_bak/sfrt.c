/****************************************************************************
 *
 * Copyright (C) 2006-2010 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/

/*
 * @file    sfrt.c
 * @author  Adam Keeton <akeeton@sourcefire.com>
 * @date    Thu July 20 10:16:26 EDT 2006
 *
 * Route implements two different routing table lookup mechanisms.  The table
 * lookups have been adapted to return a void pointer so any information can 
 * be associated with each CIDR block.  
 *
 * As of this writing, the two methods used are Stefan Nilsson and Gunnar 
 * Karlsson's LC-trie, and a multibit-trie method similar to Gupta et-al.'s 
 * DIR-n-m.  Presently, the LC-trie is used primarily for testing purposes as 
 * the current implementation does not allow for fast dynamic inserts.
 *
 * The intended use is for a user to optionally specify large IP blocks and 
 * then more specific information will be written into the routing tables 
 * from RNA.  Ideally, information will only move from less specific to more
 * specific.  If a more general information is to overwrite existing entries,
 * the table should be free'ed and rebuilt.
 * 
 *
 * Implementation:
 *
 * The routing tables associate an index into a "data" table with each CIDR.  
 * Each entry in the data table stores a pointer to actual data.  This 
 * implementation was chosen so each routing entry only needs one word to 
 * either index the data array, or point to another table.  
 *
 * Inserts are performed by specifying a CIDR and a pointer to its associated
 * data.  Since a new routing table entry may overwrite previous entries, 
 * a flag selects whether the insert favors the most recent or favors the most
 * specific.  Favoring most specific should be the default behvior.  If 
 * the user wishes to overwrite routing entries with more general data, the 
 * table should be flushed, rather than using favor-most-recent.
 * 
 * Before modifying the routing or data tables, the insert function performs a
 * lookup on the CIDR-to-be-insertted.  If no entry or an entry *of differing 
 * bit length* is found, the data is insertted into the data table, and its
 * index is used for the new routing table entry.  If an entry is found that 
 * is as specific as the new CIDR, the index stored points to where the new 
 * data is written into the data table.
 * 
 * If more specific CIDR blocks overwrote the data table, then the more 
 * general routing table entries that were not overwritten will be referencing
 * the wrong data.  Alternatively, less specific entries can only overwrite
 * existing routing table entries if favor-most-recent inserts are used.
 *
 * Because there is no quick way to clean the data-table if a user wishes to
 * use a favor-most-recent insert for more general data, the user should flush
 * the table with sfrt_free and create one anew.  Alternatively, a small 
 * memory leak occurs with the data table, as it will be storing pointers that
 * no routing table entry cares about.
 *
 *
 * The API calls that should be used are: 
 *  sfrt_new    - create new table
 *  sfrt_insert - insert entry 
 *  sfrt_lookup - lookup entry
 *  sfrt_free   - free table
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfrt.h"

char *rt_error_messages[] =
{
   "Success",
   "Insert Failure",
   "Policy Table Exceeded",
   "Dir Insert Failure",
   "Dir Lookup Failure",
   "Memory Allocation Failure"
#ifdef SUPPORT_LCTRIE
   ,
   "LC Trie Compile Failure",
   "LC Trie Insert Failure",
   "LC Trie Lookup Failure"
#endif
};

/* Create new lookup table 
 * @param   table_type Type of table. Uses the types enumeration in route.h 
 * @param   ip_type    IPv4 or IPv6. Uses the types enumeration in route.h 
 * @param   data_size  Max number of unique data entries
 *
 * Returns the new table. */
table_t *sfrt_new(char table_type, char ip_type, long data_size, uint32_t mem_cap)
{
    table_t *table = (table_t*)malloc(sizeof(table_t));

    if(!table)
    {
        return NULL;
    }

#ifndef SUP_IP6
    /* IPv6 is not supported */
    if(ip_type == IPv6)
    {
        free(table);
        return NULL;
    }
#endif

    /* If this limit is exceeded, there will be no way to distinguish
     * between pointers and indeces into the data table.  Only
     * applies to DIR-n-m. */
#ifdef SUPPORT_LCTRIE
#if SIZEOF_LONG_INT == 8
    if(data_size >= 0x800000000000000 && table_type == LCT) 
#else
    if(data_size >= 0x8000000 && table_type != LCT)
#endif
#else /* SUPPORT_LCTRIE */
#if SIZEOF_LONG_INT == 8
    if(data_size >= 0x800000000000000)
#else
    if(data_size >= 0x8000000)
#endif
#endif
    {
        free(table);
        return NULL;
    }

    /* mem_cap is specified in megabytes, but internally uses bytes. Convert */
    mem_cap *= 1024*1024;

    /* Maximum allowable number of stored entries */
    table->max_size = data_size;

    table->data = (GENERIC*)calloc(sizeof(GENERIC) * table->max_size, 1);

    if(!table->data)
    {
        free(table);
        return NULL;
    }

    table->allocated = sizeof(table_t) + sizeof(GENERIC) * table->max_size;

    table->ip_type = ip_type;
    table->table_type = table_type;

    /* This will point to the actual table lookup algorithm */
    table->rt = NULL;
#ifdef SUP_IP6
    table->rt6 = NULL;
#endif

    /* index 0 will be used for failed lookups, so set this to 1 */
    table->num_ent = 1;
    
    switch(table_type)
    {
#ifdef SUPPORT_LCTRIE
        /* Setup LC-trie table */
        case LCT:
            /* LC trie is presently not allowed  */
            table->insert = sfrt_lct_insert;
            table->lookup = sfrt_lct_lookup;
            table->free = sfrt_lct_free;
            table->usage = sfrt_lct_usage;
            table->rt = sfrt_lct_new(data_size);
            free(table->data);
            free(table);
            return NULL;

            break;
#endif            
        /* Setup DIR-n-m table */
        case DIR_24_8:
        case DIR_16x2:
        case DIR_16_8x2:
        case DIR_16_4x4:
        case DIR_8x4:
        case DIR_4x8:
        case DIR_2x16:
#ifdef SUP_IP6
        case DIR_16_4x4_16x5_4x4:
        case DIR_16x7_4x4:
        case DIR_16x8:
        case DIR_8x16:
#endif
            table->insert = sfrt_dir_insert;
            table->lookup = sfrt_dir_lookup;
            table->free = sfrt_dir_free;
            table->usage = sfrt_dir_usage;

            break;

        default:
            free(table->data);
            free(table);
            return NULL;
    };

    /* Allocate the user-specified DIR-n-m table */
    switch(table_type)
    {
        case DIR_24_8:
            table->rt = sfrt_dir_new(mem_cap, 2, 24,8);
            break;
        case DIR_16x2:
            table->rt = sfrt_dir_new(mem_cap, 2, 16,16);
            break;
        case DIR_16_8x2:
            table->rt = sfrt_dir_new(mem_cap, 3, 16,8,8);
            break;
        case DIR_16_4x4:
            table->rt = sfrt_dir_new(mem_cap, 5, 16,4,4,4,4);
            break;
        case DIR_8x4:
            table->rt = sfrt_dir_new(mem_cap, 4, 8,8,8,8);
            break;
        /* There is no reason to use 4x8 except for benchmarking and 
         * comparison purposes. */ 
        case DIR_4x8:
            table->rt = sfrt_dir_new(mem_cap, 8, 4,4,4,4,4,4,4,4);
            break;
        /* There is no reason to use 2x16 except for benchmarking and 
         * comparison purposes. */ 
        case DIR_2x16:
            table->rt = sfrt_dir_new(mem_cap, 16, 
                            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2);
            break;
#ifdef SUP_IP6
        case DIR_16_4x4_16x5_4x4:
            table->rt = sfrt_dir_new(mem_cap, 5, 16,4,4,4,4);
            table->rt6 = sfrt_dir_new(mem_cap, 14, 16,4,4,4,4,16,16,16,16,16,4,4,4,4);
            break;
        case DIR_16x7_4x4:
            table->rt = sfrt_dir_new(mem_cap, 5, 16,4,4,4,4);
            table->rt6 = sfrt_dir_new(mem_cap, 11, 16,16,16,16,16,16,16,4,4,4,4);
            break;
        case DIR_16x8:
            table->rt = sfrt_dir_new(mem_cap, 2, 16,16);
            table->rt6 = sfrt_dir_new(mem_cap, 8, 16,16,16,16,16,16,16,16);
            break;
        case DIR_8x16:
            table->rt = sfrt_dir_new(mem_cap, 4, 8,8,8,8);
            table->rt6 = sfrt_dir_new(mem_cap, 16, 
                            8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8);
            break;
#endif
    };

    if(!table->rt)
    {
        free(table->data);
        free(table);
        return NULL; 
    }

#ifdef SUP_IP6
    if (!table->rt6)
    {
        table->free( table->rt );
        free(table->data);
        free(table);
    }
#endif

    return table;
}

/* Free lookup table */
void sfrt_free(table_t *table)
{
    if(!table)
    {
        /* What are you calling me for? */
        return;
    }

    if(!table->data)
    {
        /* This really really should not have happened */
    }
    else
    {
        free(table->data);
    }

    if(!table->rt)
    {
        /* This should not have happened either */
    }
    else
    {
        table->free( table->rt );
    }

#ifdef SUP_IP6
    if(!table->rt6)
    {
        /* This should not have happened either */
    }
    else
    {
        table->free( table->rt6 );
    }
#endif

    free(table);
}

/* Perform a lookup on value contained in "ip" */
GENERIC sfrt_lookup(void *adr, table_t* table)
{
    tuple_t tuple;
#ifdef SUP_IP6
    sfip_t *ip;
#else
    uint32_t ip;
#endif
    void *rt = NULL;

    if(!adr)
    {
        return NULL;
    }

    if(!table || !table->lookup)
    {
        return NULL;
    }

#ifdef SUP_IP6
    ip = adr;
    if (ip->family == AF_INET)
    {
        rt = table->rt;
    }
    else if (ip->family == AF_INET6)
    {
        rt = table->rt6;
    }
#else
    /* IPv6 not yet supported */
    if(table->ip_type == IPv6)
    {
        return NULL;
    }

    ip = *(uint32_t*)adr;
    rt = table->rt;
#endif

    if (!rt)
    {
        return NULL;
    }

    tuple = table->lookup(ip, rt);

    if(tuple.index >= table->num_ent)
    {
        return NULL;
    }

    return table->data[tuple.index];
}

void sfrt_iterate(table_t* table, sfrt_iterator_callback userfunc)
{
    uint32_t index;
    if (!table)
        return;

    for (index = 0; index < table->num_ent; index++)
    {
        if (table->data[index])
            userfunc(table->data[index]);
    }

    return;
}

int sfrt_iterate2(table_t* table, sfrt_iterator_callback3 userfunc)
{
    uint32_t index;
    if (!table)
        return 0;

    for (index = 0; index < table->num_ent; index++)
    {
        if (table->data[index])
        {
            int ret = userfunc(table->data[index]);
            if (ret != 0)
                return ret;
        }
    }

    return 0;
}

void sfrt_cleanup2(
    table_t* table,
    sfrt_iterator_callback2 cleanup_func,
    void *data
    )
{
    uint32_t index;
    if (!table)
        return;

    for (index = 0; index < table->num_ent; index++)
    {
        if (table->data[index])
            cleanup_func(table->data[index], data);

        /* cleanup_func is supposed to free memory associated with this
         * table->data[index].  Set that to NULL.
         */
        table->data[index] = NULL;
    }
}

void sfrt_cleanup(table_t* table, sfrt_iterator_callback cleanup_func)
{
    uint32_t index;
    if (!table)
        return;

    for (index = 0; index < table->num_ent; index++)
    {
        if (table->data[index])
            cleanup_func(table->data[index]);

        /* cleanup_func is supposed to free memory associated with this
         * table->data[index].  Set that to NULL.
         */
        table->data[index] = NULL;
    }

    return;
}

GENERIC sfrt_search(void *adr, unsigned char len, table_t *table)
{
#ifdef SUP_IP6
    sfip_t *ip;
#else
    uint32_t ip;
#endif
    tuple_t tuple; 
    void *rt = NULL;

    if ((adr == NULL) || (table == NULL) || (len == 0))
        return NULL;

#ifdef SUP_IP6
    ip = adr;
    if (ip->family == AF_INET)
    {
        rt = table->rt;
    }
    else if (ip->family == AF_INET6)
    {
        rt = table->rt6;
    }
#else
    /* IPv6 not yet supported */
    if(table->ip_type == IPv6)
    {
        return NULL;
    }

    ip = *(uint32_t*)adr;
    rt = table->rt;
#endif
    /* IPv6 not yet supported */
    if (table->ip_type == IPv6)
        return NULL;

    if( (table->ip_type == IPv4 && len > 32) ||
        (table->ip_type == IPv6 && len > 128) )
    {
        return NULL;
    }

#ifdef SUP_IP6
    ip = adr;
#else
    ip = *(uint32_t*)adr;
#endif

    tuple = table->lookup(ip, rt);

    if (tuple.length != len)
        return NULL;

    return table->data[tuple.index];
}

/* Insert "ip", of length "len", into "table", and have it point to "ptr" */
/* Insert "ip", of length "len", into "table", and have it point to "ptr" */
int sfrt_insert(void *adr, unsigned char len, GENERIC ptr,
					   int behavior, table_t *table)
{
    int index;
    int res;
#ifdef SUP_IP6
    sfip_t *ip;
#else
    uint32_t ip;
#endif
    tuple_t tuple; 
    void *rt = NULL;

    if(!adr)
    {
        return RT_INSERT_FAILURE;
    }

    if (len == 0)
        return RT_INSERT_FAILURE;

    if(!table || !table->insert || !table->data || !table->lookup)
    {
        return RT_INSERT_FAILURE;
    }
        
    if( (table->ip_type == IPv4 && len > 32) ||
        (table->ip_type == IPv6 && len > 128) )
    {
        return RT_INSERT_FAILURE;
    }

#ifdef SUP_IP6
    ip = adr;
#else
    ip = *(uint32_t*)adr;
#endif

    /* Check if we can reuse an existing data table entry by 
     * seeing if there is an existing entry with the same length. */
    /* Only perform this if the table is not an LC-trie */
#ifdef SUPPORT_LCTRIE
    if(table->table_type != LCT)
    {
#endif

#ifdef SUP_IP6
        if (ip->family == AF_INET)
        {
            rt = table->rt;
        }
        else if (ip->family == AF_INET6)
        {
            rt = table->rt6;
        }
#else
        rt = table->rt;
#endif
        if (!rt)
        {
            return RT_INSERT_FAILURE;
        }

        tuple = table->lookup(ip, table->rt);

#ifdef SUPPORT_LCTRIE
    }
#endif

#ifdef SUPPORT_LCTRIE
    if(table->table_type == LCT || tuple.length != len)
    {
#else
    if(tuple.length != len)
    {
#endif
        if( table->num_ent >= table->max_size)
        {
            return RT_POLICY_TABLE_EXCEEDED; 
        }

        index = table->num_ent;
        table->num_ent++;
    } 
    else
    {
        index = tuple.index;
    }

    /* Insert value into policy table */
    table->data[ index ] = ptr;

    /* The actual value that is looked-up is an index 
     * into the data table. */
    res = table->insert(ip, len, index, behavior, rt);

    /* Check if we ran out of memory. If so, need to decrement 
     * table->num_ent */
    if(res == MEM_ALLOC_FAILURE)
    {
        /* From the control flow above, it's possible table->num_ent was not
         * incremented.  It should be safe to decrement here, because the only
         * time it will be incremented above is when we are potentially 
         * mallocing one or more new entries (It's not incremented when we
         * overwrite an existing entry). */
        table->num_ent--;    
    }
    
    return res;
}

uint32_t sfrt_num_entries(table_t *table)
{
    if(!table || !table->rt || !table->allocated)
    {
        return 0;
    }
    
    /* There is always a root node, so subtract 1 for it */
    return table->num_ent - 1;
}

uint32_t sfrt_usage(table_t *table)
{
    uint32_t usage;
    if(!table || !table->rt || !table->allocated || !table->usage)
    {
        return 0;
    }
    
    usage = table->allocated + table->usage( table->rt );

#ifdef SUP_IP6
    if (table->rt6)
    {
        usage += table->usage( table->rt6 ); 
    }
#endif

    return usage;
}

#ifdef DEBUG_SFRT

#define NUM_IPS 32
#define NUM_DATA 4

int main()
{
    table_t *dir;
    uint32_t ip_list[NUM_IPS];  /* entirely arbitrary */
    char data[NUM_DATA];     /* also entirely arbitrary */
    uint32_t index, val;

    for(index=0; index<NUM_IPS; index++)
    {
        ip_list[index] = (uint32_t)rand()%NUM_IPS;
        data[index%NUM_DATA] = index%26 + 65;    /* Random letter */ 
    }
        
    dir = sfrt_new(DIR_16x2, IPv4, NUM_IPS, 20);

    if(!dir)
    {
        printf("Failed to create DIR\n");
        return 1;
    }

    for(index=0; index < NUM_IPS; index++)
    {
        if(sfrt_insert(&ip_list[index], 32, &data[index%NUM_DATA], 
                       RT_FAVOR_SPECIFIC, dir) != RT_SUCCESS)
        {
            printf("DIR Insertion failure\n");
            return 1;
        }

        printf("%d\t %x: %c -> %c\n", index, ip_list[index], 
              data[index%NUM_DATA], *(uint32_t*)sfrt_lookup(&ip_list[index], dir));

    }   

    for(index=0; index < NUM_IPS; index++)
    {
        val = *(uint32_t*)sfrt_lookup(&ip_list[index], dir);
        printf("\t@%d\t%x: %c.  originally:\t%c\n", 
                            index, ip_list[index], val, data[index%NUM_DATA]);
    }   

    printf("Usage: %d bytes\n", ((dir_table_t*)(dir->rt))->allocated);
    
    sfrt_free(dir);
    return 0;
}

#endif /* DEBUG_SFRT */

