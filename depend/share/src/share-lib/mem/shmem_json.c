

/*
 * @copyright
 *
 *  Copyright 2011 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */

/*
  Copyright (c) 2009 Dave Gamble

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include "share.h"
#include "shmem.h"

typedef struct shjson_Hooks {
      void *(*malloc_fn)(size_t sz);
      void (*free_fn)(void *ptr);
} shjson_Hooks;

/* Supply malloc, realloc and free functions to shjson_t */
void shjson_InitHooks(shjson_Hooks* hooks);


/* Supply a block of JSON, and this returns a shjson_t object you can interrogate. Call shjson_Delete when finished. */
shjson_t *shjson_Parse(const char *value);
/* Render a shjson_t entity to text for transfer/storage. Free the char* when finished. */
char  *shjson_Print(shjson_t *item);
/* Render a shjson_t entity to text for transfer/storage without any formatting. Free the char* when finished. */
char  *shjson_PrintUnformatted(shjson_t *item);
/* Delete a shjson_t entity and all subentities. */
static void   shjson_Delete(shjson_t *c);

/* Returns the number of items in an array (or object). */
int	  shjson_GetArraySize(shjson_t *array);
/* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
shjson_t *shjson_GetArrayItem(shjson_t *array,int item);
/* Get item "string" from object. Case insensitive. */
shjson_t *shjson_GetObjectItem(shjson_t *object,const char *string);

/* For analysing failed parses. This returns a pointer to the parse error. You'll probably need to look a few chars back to make sense of it. Defined when shjson_Parse() returns 0. 0 when shjson_Parse() succeeds. */
const char *shjson_GetErrorPtr(void);
	
/* These calls create a shjson_t item of the appropriate type. */
shjson_t *shjson_CreateNull(void);
shjson_t *shjson_CreateTrue(void);
shjson_t *shjson_CreateFalse(void);
shjson_t *shjson_CreateBool(int b);
shjson_t *shjson_CreateNumber(double num);
shjson_t *shjson_CreateString(const char *string);
shjson_t *shjson_CreateArray(void);
shjson_t *shjson_CreateObject(void);

/* These utilities create an Array of count items. */
shjson_t *shjson_CreateIntArray(const int *numbers,int count);
shjson_t *shjson_CreateFloatArray(const float *numbers,int count);
shjson_t *shjson_CreateDoubleArray(const double *numbers,int count);
shjson_t *shjson_CreateStringArray(const char **strings,int count);

/* Append item to the specified array/object. */
void shjson_AddItemToArray(shjson_t *array, shjson_t *item);
void	shjson_AddItemToObject(shjson_t *object,const char *string,shjson_t *item);
/* Append reference to item to the specified array/object. Use this when you want to add an existing shjson_t to a new shjson_t, but don't want to corrupt your existing shjson_t. */
void shjson_AddItemReferenceToArray(shjson_t *array, shjson_t *item);
void	shjson_AddItemReferenceToObject(shjson_t *object,const char *string,shjson_t *item);

/* Remove/Detatch items from Arrays/Objects. */
shjson_t *shjson_DetachItemFromArray(shjson_t *array,int which);
void   shjson_DeleteItemFromArray(shjson_t *array,int which);
shjson_t *shjson_DetachItemFromObject(shjson_t *object,const char *string);
void   shjson_DeleteItemFromObject(shjson_t *object,const char *string);
	
/* Update array items. */
void shjson_ReplaceItemInArray(shjson_t *array,int which,shjson_t *newitem);
void shjson_ReplaceItemInObject(shjson_t *object,const char *string,shjson_t *newitem);

/* Duplicate a shjson_t item */
shjson_t *shjson_Duplicate(shjson_t *item,int recurse);
/* Duplicate will create a new, identical shjson_t item to the one you pass, in new memory that will
need to be released. With recurse!=0, it will duplicate any children connected to the item.
The item->next and ->prev pointers are always zero on return from Duplicate. */

/* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
shjson_t *shjson_ParseWithOpts(const char *value,const char **return_parse_end,int require_null_terminated);

void shjson_Minify(char *json);

/* Macros for creating things quickly. */
#define shjson_AddNullToObject(object,name)		shjson_AddItemToObject(object, name, shjson_CreateNull())
#define shjson_AddTrueToObject(object,name)		shjson_AddItemToObject(object, name, shjson_CreateTrue())
#define shjson_AddFalseToObject(object,name)		shjson_AddItemToObject(object, name, shjson_CreateFalse())
#define shjson_AddBoolToObject(object,name,b)	shjson_AddItemToObject(object, name, shjson_CreateBool(b))
#define shjson_AddNumberToObject(object,name,n)	shjson_AddItemToObject(object, name, shjson_CreateNumber(n))
#define shjson_AddStringToObject(object,name,s)	shjson_AddItemToObject(object, name, shjson_CreateString(s))

/* When assigning an integer value, it needs to be propagated to valuedouble too. */
#define shjson_SetIntValue(object,val)			((object)?(object)->valueint=(object)->valuedouble=(val):(val))



static const char *ep;

const char *shjson_GetErrorPtr(void) {return ep;}

static int shjson_strcasecmp(const char *s1,const char *s2)
{
	if (!s1) return (s1==s2)?0:1;if (!s2) return 1;
	for(; tolower(*s1) == tolower(*s2); ++s1, ++s2)	if(*s1 == 0)	return 0;
	return tolower(*(const unsigned char *)s1) - tolower(*(const unsigned char *)s2);
}

static void *(*shjson_malloc)(size_t sz) = malloc;
static void (*shjson_FreeMem)(void *ptr) = free;

static char* shjson_strdup(const char* str)
{
      size_t len;
      char* copy;

      len = strlen(str) + 1;
      if (!(copy = (char*)shjson_malloc(len))) return 0;
      memcpy(copy,str,len);
      return copy;
}

void shjson_InitHooks(shjson_Hooks* hooks)
{
    if (!hooks) { /* Reset hooks */
        shjson_malloc = malloc;
        shjson_FreeMem = free;
        return;
    }

	shjson_malloc = (hooks->malloc_fn)?hooks->malloc_fn:malloc;
	shjson_FreeMem	 = (hooks->free_fn)?hooks->free_fn:free;
}

/* Internal constructor. */
static shjson_t *shjson_New_Item(void)
{
	shjson_t* node = (shjson_t*)shjson_malloc(sizeof(shjson_t));
	if (node) memset(node,0,sizeof(shjson_t));
	return node;
}

/* Delete a shjson_t structure. */
static void shjson_Delete(shjson_t *c)
{
	shjson_t *next;
	while (c)
	{
		next=c->next;
		if (!(c->type&SHJSON_REFERENCE) && c->child) shjson_Delete(c->child);
		if (!(c->type&SHJSON_REFERENCE) && c->valuestring) shjson_FreeMem(c->valuestring);
		if (c->string) shjson_FreeMem(c->string);
		shjson_FreeMem(c);
		c=next;
	}
}

/* Parse the input text to generate a number, and populate the result into item. */
static const char *parse_number(shjson_t *item,const char *num)
{
	double n=0,sign=1,scale=0;int subscale=0,signsubscale=1;

	if (*num=='-') sign=-1,num++;	/* Has sign? */
	if (*num=='0') num++;			/* is zero */
	if (*num>='1' && *num<='9')	do	n=(n*10.0)+(*num++ -'0');	while (*num>='0' && *num<='9');	/* Number? */
	if (*num=='.' && num[1]>='0' && num[1]<='9') {num++;		do	n=(n*10.0)+(*num++ -'0'),scale--; while (*num>='0' && *num<='9');}	/* Fractional part? */
	if (*num=='e' || *num=='E')		/* Exponent? */
	{	num++;if (*num=='+') num++;	else if (*num=='-') signsubscale=-1,num++;		/* With sign? */
		while (*num>='0' && *num<='9') subscale=(subscale*10)+(*num++ - '0');	/* Number? */
	}

	n=sign*n*pow(10.0,(scale+subscale*signsubscale));	/* number = +/- number.fraction * 10^+/- exponent */
	
	item->valuedouble=n;
	item->valueint=(int)n;
	item->type=SHJSON_NUMBER;
	return num;
}

/* Render the number nicely from the given item into a string. */
static char *print_number(shjson_t *item)
{
	char *str;
	double d=item->valuedouble;
	if (fabs(((double)item->valueint)-d)<=DBL_EPSILON && d<=INT_MAX && d>=INT_MIN)
	{
		str=(char*)shjson_malloc(21);	/* 2^64+1 can be represented in 21 chars. */
		if (str) sprintf(str,"%d",item->valueint);
	}
	else
	{
		str=(char*)shjson_malloc(64);	/* This is a nice tradeoff. */
		if (str)
		{
			if (fabs(floor(d)-d)<=DBL_EPSILON && fabs(d)<1.0e60)sprintf(str,"%.0f",d);
			else if (fabs(d)<1.0e-6 || fabs(d)>1.0e9)			sprintf(str,"%e",d);
			else												sprintf(str,"%f",d);
		}
	}
	return str;
}

double shjson_num(shjson_t *json, char *name, double def_d)
{
  shjson_t *item;
	double d;

  if (!json)
    return (0);

  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (def_d);
  } else {
    item = json;
  }

  d = item->valuedouble;
	if (fabs(((double)item->valueint)-d)<=DBL_EPSILON && d<=INT_MAX && d>=INT_MIN) {
		d = (double)item->valueint;
	}

	return (d);
}

int shjson_bool(shjson_t *json, char *name, int def_d)
{
  shjson_t *item;
	double d;

  if (!json)
    return (0);

  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (def_d);
  } else {
    item = json;
  }

	if (item->type == SHJSON_TRUE)
		return (TRUE);

	return (FALSE);
}

int shjson_type(shjson_t *json, char *name)
{
	int type;

	if (name) {
		json = shjson_GetObjectItem(json, name);
	}
	if (!json)
		return (SHJSON_NULL);

	type = json->type & 255;
	if (type == SHJSON_TRUE ||
			type == SHJSON_FALSE)
		return (SHJSON_BOOLEAN);

	return (type);
}

char *shjson_astr(shjson_t *json, char *name, char *def_str)
{
  shjson_t *item;
  char *str;

  if (!json)
    return (NULL);

  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (def_str);
  } else {
    item = json;
  }

  return (item->valuestring);
}

char *shjson_str(shjson_t *json, char *name, char *def_str)
{
  char *str = shjson_astr(json, name, def_str);
  if (!str)
    return (NULL);
  return (strdup(str));
}

shjson_t *shjson_obj(shjson_t *json, char *name)
{
  shjson_t *item;
  char *str;

  if (!json)
    return (NULL);

  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (NULL);
  } else {
    item = json;
  }

  return (item);
}

size_t shjson_strlen(shjson_t *json, char *name)
{
  char *str = shjson_astr(json, name, "");
  if (!str)
    return (0);
  return ((size_t)strlen(str));
}

uint64_t shjson_crc(shjson_t *json, char *name)
{
	if (name)
		json = shjson_obj_get(json, name);

	if (json->type == SHJSON_STRING) {
		return (shcrc(json->valuestring, strlen(json->valuestring)));
	} 

	if (json->type == SHJSON_NUMBER) {
		double d;

		d = json->valuedouble;
		if (fabs(((double)json->valueint)-d)<=DBL_EPSILON && d<=INT_MAX && d>=INT_MIN) {
			d = (double)json->valueint;
		}

		return (shcrc(&d, sizeof(d)));
	}

	return (shcrc(&json->type, sizeof(json->type)));
}

static unsigned parse_hex4(const char *str)
{
	unsigned h=0;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	return h;
}

/* Parse the input text into an unescaped cstring, and populate item. */
static const unsigned char firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const char *parse_string(shjson_t *item,const char *str)
{
	const char *ptr=str+1;char *ptr2;char *out;int len=0;unsigned uc,uc2;
	if (*str!='\"') {ep=str;return 0;}	/* not a string! */
	
	while (*ptr!='\"' && *ptr && ++len) if (*ptr++ == '\\') ptr++;	/* Skip escaped quotes. */
	
	out=(char*)shjson_malloc(len+1);	/* This is how long we need for the string, roughly. */
	if (!out) return 0;
	
	ptr=str+1;ptr2=out;
	while (*ptr!='\"' && *ptr)
	{
		if (*ptr!='\\') *ptr2++=*ptr++;
		else
		{
			ptr++;
			switch (*ptr)
			{
				case 'b': *ptr2++='\b';	break;
				case 'f': *ptr2++='\f';	break;
				case 'n': *ptr2++='\n';	break;
				case 'r': *ptr2++='\r';	break;
				case 't': *ptr2++='\t';	break;
				case 'u':	 /* transcode utf16 to utf8. */
					uc=parse_hex4(ptr+1);ptr+=4;	/* get the unicode char. */

					if ((uc>=0xDC00 && uc<=0xDFFF) || uc==0)	break;	/* check for invalid.	*/

					if (uc>=0xD800 && uc<=0xDBFF)	/* UTF16 surrogate pairs.	*/
					{
						if (ptr[1]!='\\' || ptr[2]!='u')	break;	/* missing second-half of surrogate.	*/
						uc2=parse_hex4(ptr+3);ptr+=6;
						if (uc2<0xDC00 || uc2>0xDFFF)		break;	/* invalid second-half of surrogate.	*/
						uc=0x10000 + (((uc&0x3FF)<<10) | (uc2&0x3FF));
					}

					len=4;if (uc<0x80) len=1;else if (uc<0x800) len=2;else if (uc<0x10000) len=3; ptr2+=len;
					
					switch (len) {
						case 4: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
						case 3: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
						case 2: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
						case 1: *--ptr2 =(uc | firstByteMark[len]);
					}
					ptr2+=len;
					break;
				default:  *ptr2++=*ptr; break;
			}
			ptr++;
		}
	}
	*ptr2=0;
	if (*ptr=='\"') ptr++;
	item->valuestring=out;
	item->type=SHJSON_STRING;
	return ptr;
}

/* Render the cstring provided to an escaped version that can be printed. */
static char *print_string_ptr(const char *str)
{
	const char *ptr;char *ptr2,*out;int len=0;unsigned char token;
	
	if (!str) return shjson_strdup("\"\"");
	ptr=str;while ((token=*ptr) && ++len) {if (strchr("\"\\\b\f\n\r\t",token)) len++; else if (token<32) len+=5;ptr++;}
	
	out=(char*)shjson_malloc(len+3);
	if (!out) return 0;

	ptr2=out;ptr=str;
	*ptr2++='\"';
	while (*ptr)
	{
		if ((unsigned char)*ptr>31 && *ptr!='\"' && *ptr!='\\') *ptr2++=*ptr++;
		else
		{
			*ptr2++='\\';
			switch (token=*ptr++)
			{
				case '\\':	*ptr2++='\\';	break;
				case '\"':	*ptr2++='\"';	break;
				case '\b':	*ptr2++='b';	break;
				case '\f':	*ptr2++='f';	break;
				case '\n':	*ptr2++='n';	break;
				case '\r':	*ptr2++='r';	break;
				case '\t':	*ptr2++='t';	break;
				default: sprintf(ptr2,"u%04x",token);ptr2+=5;	break;	/* escape and print */
			}
		}
	}
	*ptr2++='\"';*ptr2++=0;
	return out;
}
/* Invote print_string_ptr (which is useful) on an item. */
static char *print_string(shjson_t *item)	{return print_string_ptr(item->valuestring);}

/* Predeclare these prototypes. */
static const char *parse_value(shjson_t *item,const char *value);
static char *print_value(shjson_t *item,int depth,int fmt);
static const char *parse_array(shjson_t *item,const char *value);
static char *print_array(shjson_t *item,int depth,int fmt);
static const char *parse_object(shjson_t *item,const char *value);
static char *print_object(shjson_t *item,int depth,int fmt);

/* Utility to jump whitespace and cr/lf */
static const char *skip(const char *in) {while (in && *in && (unsigned char)*in<=32) in++; return in;}

/* Parse an object - create a new root, and populate. */
shjson_t *shjson_ParseWithOpts(const char *value,const char **return_parse_end,int require_null_terminated)
{
	const char *end=0;
	shjson_t *c=shjson_New_Item();
	ep=0;
	if (!c) return 0;       /* memory fail */

	end=parse_value(c,skip(value));
	if (!end)	{shjson_Delete(c);return 0;}	/* parse failure. ep is set. */

	/* if we require null-terminated JSON without appended garbage, skip and then check for a null terminator */
	if (require_null_terminated) {end=skip(end);if (*end) {shjson_Delete(c);ep=end;return 0;}}
	if (return_parse_end) *return_parse_end=end;
	return c;
}
/* Default options for shjson_Parse */
shjson_t *shjson_Parse(const char *value) {return shjson_ParseWithOpts(value,0,0);}

/* Render a shjson_t item/entity/structure to text. */
char *shjson_Print(shjson_t *item)				{return print_value(item,0,1);}
char *shjson_PrintUnformatted(shjson_t *item)	{return print_value(item,0,0);}

/* Parser core - when encountering text, process appropriately. */
static const char *parse_value(shjson_t *item,const char *value)
{
	if (!value)						return 0;	/* Fail on null. */
	if (!strncmp(value,"null",4))	{ item->type=SHJSON_NULL;  return value+4; }
	if (!strncmp(value,"false",5))	{ item->type=SHJSON_FALSE; return value+5; }
	if (!strncmp(value,"true",4))	{ item->type=SHJSON_TRUE; item->valueint=1;	return value+4; }
	if (*value=='\"')				{ return parse_string(item,value); }
	if (*value=='-' || (*value>='0' && *value<='9'))	{ return parse_number(item,value); }
	if (*value=='[')				{ return parse_array(item,value); }
	if (*value=='{')				{ return parse_object(item,value); }

	ep=value;return 0;	/* failure. */
}

/* Render a value to text. */
static char *print_value(shjson_t *item,int depth,int fmt)
{
	char *out=0;
	if (!item) return 0;
	switch ((item->type)&255)
	{
		case SHJSON_NULL:	out=shjson_strdup("null");	break;
		case SHJSON_FALSE:	out=shjson_strdup("false");break;
		case SHJSON_TRUE:	out=shjson_strdup("true"); break;
		case SHJSON_NUMBER:	out=print_number(item);break;
		case SHJSON_STRING:	out=print_string(item);break;
		case SHJSON_ARRAY:	out=print_array(item,depth,fmt);break;
		case SHJSON_OBJECT:	out=print_object(item,depth,fmt);break;
	}
	return out;
}

/* Build an array from input text. */
static const char *parse_array(shjson_t *item,const char *value)
{
	shjson_t *child;
	if (*value!='[')	{ep=value;return 0;}	/* not an array! */

	item->type=SHJSON_ARRAY;
	value=skip(value+1);
	if (*value==']') return value+1;	/* empty array. */

	item->child=child=shjson_New_Item();
	if (!item->child) return 0;		 /* memory fail */
	value=skip(parse_value(child,skip(value)));	/* skip any spacing, get the value. */
	if (!value) return 0;

	while (*value==',')
	{
		shjson_t *new_item;
		if (!(new_item=shjson_New_Item())) return 0; 	/* memory fail */
		child->next=new_item;new_item->prev=child;child=new_item;
		value=skip(parse_value(child,skip(value+1)));
		if (!value) return 0;	/* memory fail */
	}

	if (*value==']') return value+1;	/* end of array */
	ep=value;return 0;	/* malformed. */
}

/* Render an array to text */
static char *print_array(shjson_t *item,int depth,int fmt)
{
	char **entries;
	char *out=0,*ptr,*ret;int len=5;
	shjson_t *child=item->child;
	int numentries=0,i=0,fail=0;
	
	/* How many entries in the array? */
	while (child) numentries++,child=child->next;
	/* Explicitly handle numentries==0 */
	if (!numentries)
	{
		out=(char*)shjson_malloc(3);
		if (out) strcpy(out,"[]");
		return out;
	}
	/* Allocate an array to hold the values for each */
	entries=(char**)shjson_malloc(numentries*sizeof(char*));
	if (!entries) return 0;
	memset(entries,0,numentries*sizeof(char*));
	/* Retrieve all the results: */
	child=item->child;
	while (child && !fail)
	{
		ret=print_value(child,depth+1,fmt);
		entries[i++]=ret;
		if (ret) len+=strlen(ret)+2+(fmt?1:0); else fail=1;
		child=child->next;
	}
	
	/* If we didn't fail, try to malloc the output string */
	if (!fail) out=(char*)shjson_malloc(len);
	/* If that fails, we fail. */
	if (!out) fail=1;

	/* Handle failure. */
	if (fail)
	{
		for (i=0;i<numentries;i++) if (entries[i]) shjson_FreeMem(entries[i]);
		shjson_FreeMem(entries);
		return 0;
	}
	
	/* Compose the output array. */
	*out='[';
	ptr=out+1;*ptr=0;
	for (i=0;i<numentries;i++)
	{
		strcpy(ptr,entries[i]);ptr+=strlen(entries[i]);
		if (i!=numentries-1) {*ptr++=',';if(fmt)*ptr++=' ';*ptr=0;}
		shjson_FreeMem(entries[i]);
	}
	shjson_FreeMem(entries);
	*ptr++=']';*ptr++=0;
	return out;	
}

/* Build an object from the text. */
static const char *parse_object(shjson_t *item,const char *value)
{
	shjson_t *child;
	if (*value!='{')	{ep=value;return 0;}	/* not an object! */
	
	item->type=SHJSON_OBJECT;
	value=skip(value+1);
	if (*value=='}') return value+1;	/* empty array. */
	
	item->child=child=shjson_New_Item();
	if (!item->child) return 0;
	value=skip(parse_string(child,skip(value)));
	if (!value) return 0;
	child->string=child->valuestring;child->valuestring=0;
	if (*value!=':') {ep=value;return 0;}	/* fail! */
	value=skip(parse_value(child,skip(value+1)));	/* skip any spacing, get the value. */
	if (!value) return 0;
	
	while (*value==',')
	{
		shjson_t *new_item;
		if (!(new_item=shjson_New_Item()))	return 0; /* memory fail */
		child->next=new_item;new_item->prev=child;child=new_item;
		value=skip(parse_string(child,skip(value+1)));
		if (!value) return 0;
		child->string=child->valuestring;child->valuestring=0;
		if (*value!=':') {ep=value;return 0;}	/* fail! */
		value=skip(parse_value(child,skip(value+1)));	/* skip any spacing, get the value. */
		if (!value) return 0;
	}
	
	if (*value=='}') return value+1;	/* end of array */
	ep=value;return 0;	/* malformed. */
}

/* Render an object to text. */
static char *print_object(shjson_t *item,int depth,int fmt)
{
	char **entries=0,**names=0;
	char *out=0,*ptr,*ret,*str;int len=7,i=0,j;
	shjson_t *child=item->child;
	int numentries=0,fail=0;
	/* Count the number of entries. */
	while (child) numentries++,child=child->next;
	/* Explicitly handle empty object case */
	if (!numentries)
	{
		out=(char*)shjson_malloc(fmt?depth+4:3);
		if (!out)	return 0;
		ptr=out;*ptr++='{';
		if (fmt) {*ptr++='\n';for (i=0;i<depth-1;i++) *ptr++='\t';}
		*ptr++='}';*ptr++=0;
		return out;
	}
	/* Allocate space for the names and the objects */
	entries=(char**)shjson_malloc(numentries*sizeof(char*));
	if (!entries) return 0;
	names=(char**)shjson_malloc(numentries*sizeof(char*));
	if (!names) {shjson_FreeMem(entries);return 0;}
	memset(entries,0,sizeof(char*)*numentries);
	memset(names,0,sizeof(char*)*numentries);

	/* Collect all the results into our arrays: */
	child=item->child;depth++;if (fmt) len+=depth;
	while (child)
	{
		names[i]=str=print_string_ptr(child->string);
		entries[i++]=ret=print_value(child,depth,fmt);
		if (str && ret) len+=strlen(ret)+strlen(str)+2+(fmt?2+depth:0); else fail=1;
		child=child->next;
	}
	
	/* Try to allocate the output string */
	if (!fail) out=(char*)shjson_malloc(len);
	if (!out) fail=1;

	/* Handle failure */
	if (fail)
	{
		for (i=0;i<numentries;i++) {if (names[i]) shjson_FreeMem(names[i]);if (entries[i]) shjson_FreeMem(entries[i]);}
		shjson_FreeMem(names);shjson_FreeMem(entries);
		return 0;
	}
	
	/* Compose the output: */
	*out='{';ptr=out+1;if (fmt)*ptr++='\n';*ptr=0;
	for (i=0;i<numentries;i++)
	{
		if (fmt) for (j=0;j<depth;j++) *ptr++='\t';
		strcpy(ptr,names[i]);ptr+=strlen(names[i]);
		*ptr++=':';if (fmt) *ptr++='\t';
		strcpy(ptr,entries[i]);ptr+=strlen(entries[i]);
		if (i!=numentries-1) *ptr++=',';
		if (fmt) *ptr++='\n';*ptr=0;
		shjson_FreeMem(names[i]);shjson_FreeMem(entries[i]);
	}
	
	shjson_FreeMem(names);shjson_FreeMem(entries);
	if (fmt) for (i=0;i<depth-1;i++) *ptr++='\t';
	*ptr++='}';*ptr++=0;
	return out;	
}

/* Get Array size/item / object item. */
int    shjson_GetArraySize(shjson_t *array)							{shjson_t *c=array->child;int i=0;while(c)i++,c=c->next;return i;}
shjson_t *shjson_GetArrayItem(shjson_t *array,int item)				{shjson_t *c=array->child;  while (c && item>0) item--,c=c->next; return c;}
shjson_t *shjson_GetObjectItem(shjson_t *object,const char *string)	{shjson_t *c=object->child; while (c && shjson_strcasecmp(c->string,string)) c=c->next; return c;}

/* Utility for array list handling. */
static void suffix_object(shjson_t *prev,shjson_t *item) {prev->next=item;item->prev=prev;}
/* Utility for handling references. */
static shjson_t *create_reference(shjson_t *item) {shjson_t *ref=shjson_New_Item();if (!ref) return 0;memcpy(ref,item,sizeof(shjson_t));ref->string=0;ref->type|=SHJSON_REFERENCE;ref->next=ref->prev=0;return ref;}

/* Add item to array/object. */
void   shjson_AddItemToArray(shjson_t *array, shjson_t *item)						{shjson_t *c=array->child;if (!item) return; if (!c) {array->child=item;} else {while (c && c->next) c=c->next; suffix_object(c,item);}}
void   shjson_AddItemToObject(shjson_t *object,const char *string,shjson_t *item)	{if (!item) return; if (item->string) shjson_FreeMem(item->string);item->string=shjson_strdup(string);shjson_AddItemToArray(object,item);}
void	shjson_AddItemReferenceToArray(shjson_t *array, shjson_t *item)						{shjson_AddItemToArray(array,create_reference(item));}
void	shjson_AddItemReferenceToObject(shjson_t *object,const char *string,shjson_t *item)	{shjson_AddItemToObject(object,string,create_reference(item));}

shjson_t *shjson_DetachItemFromArray(shjson_t *array,int which)			{shjson_t *c=array->child;while (c && which>0) c=c->next,which--;if (!c) return 0;
	if (c->prev) c->prev->next=c->next;if (c->next) c->next->prev=c->prev;if (c==array->child) array->child=c->next;c->prev=c->next=0;return c;}
void   shjson_DeleteItemFromArray(shjson_t *array,int which)			{shjson_Delete(shjson_DetachItemFromArray(array,which));}
shjson_t *shjson_DetachItemFromObject(shjson_t *object,const char *string) {int i=0;shjson_t *c=object->child;while (c && shjson_strcasecmp(c->string,string)) i++,c=c->next;if (c) return shjson_DetachItemFromArray(object,i);return 0;}
void   shjson_DeleteItemFromObject(shjson_t *object,const char *string) {shjson_Delete(shjson_DetachItemFromObject(object,string));}

/* Replace array/object items with new ones. */
void   shjson_ReplaceItemInArray(shjson_t *array,int which,shjson_t *newitem)		{shjson_t *c=array->child;while (c && which>0) c=c->next,which--;if (!c) return;
	newitem->next=c->next;newitem->prev=c->prev;if (newitem->next) newitem->next->prev=newitem;
	if (c==array->child) array->child=newitem; else newitem->prev->next=newitem;c->next=c->prev=0;shjson_Delete(c);}
void   shjson_ReplaceItemInObject(shjson_t *object,const char *string,shjson_t *newitem){int i=0;shjson_t *c=object->child;while(c && shjson_strcasecmp(c->string,string))i++,c=c->next;if(c){newitem->string=shjson_strdup(string);shjson_ReplaceItemInArray(object,i,newitem);}}

/* Create basic types: */
shjson_t *shjson_CreateNull(void)					{shjson_t *item=shjson_New_Item();if(item)item->type=SHJSON_NULL;return item;}
shjson_t *shjson_CreateTrue(void)					{shjson_t *item=shjson_New_Item();if(item)item->type=SHJSON_TRUE;return item;}
shjson_t *shjson_CreateFalse(void)					{shjson_t *item=shjson_New_Item();if(item)item->type=SHJSON_FALSE;return item;}
shjson_t *shjson_CreateBool(int b)					{shjson_t *item=shjson_New_Item();if(item)item->type=b?SHJSON_TRUE:SHJSON_FALSE;return item;}
shjson_t *shjson_CreateNumber(double num)			{shjson_t *item=shjson_New_Item();if(item){item->type=SHJSON_NUMBER;item->valuedouble=num;item->valueint=(int)num;}return item;}
shjson_t *shjson_CreateString(const char *string)	{shjson_t *item=shjson_New_Item();if(item){item->type=SHJSON_STRING;item->valuestring=shjson_strdup(string);}return item;}
shjson_t *shjson_CreateArray(void)					{shjson_t *item=shjson_New_Item();if(item)item->type=SHJSON_ARRAY;return item;}
shjson_t *shjson_CreateObject(void)					{shjson_t *item=shjson_New_Item();if(item)item->type=SHJSON_OBJECT;return item;}

/* Create Arrays: */
shjson_t *shjson_CreateIntArray(const int *numbers,int count)		{int i;shjson_t *n=0,*p=0,*a=shjson_CreateArray();for(i=0;a && i<count;i++){n=shjson_CreateNumber(numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
shjson_t *shjson_CreateFloatArray(const float *numbers,int count)	{int i;shjson_t *n=0,*p=0,*a=shjson_CreateArray();for(i=0;a && i<count;i++){n=shjson_CreateNumber(numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
shjson_t *shjson_CreateDoubleArray(const double *numbers,int count)	{int i;shjson_t *n=0,*p=0,*a=shjson_CreateArray();for(i=0;a && i<count;i++){n=shjson_CreateNumber(numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
shjson_t *shjson_CreateStringArray(const char **strings,int count)	{int i;shjson_t *n=0,*p=0,*a=shjson_CreateArray();for(i=0;a && i<count;i++){n=shjson_CreateString(strings[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}

/* Duplication */
shjson_t *shjson_Duplicate(shjson_t *item,int recurse)
{
	shjson_t *newitem,*cptr,*nptr=0,*newchild;
	/* Bail on bad ptr */
	if (!item) return 0;
	/* Create new item */
	newitem=shjson_New_Item();
	if (!newitem) return 0;
	/* Copy over all vars */
	newitem->type=item->type&(~SHJSON_REFERENCE),newitem->valueint=item->valueint,newitem->valuedouble=item->valuedouble;
	if (item->valuestring)	{newitem->valuestring=shjson_strdup(item->valuestring);	if (!newitem->valuestring)	{shjson_Delete(newitem);return 0;}}
	if (item->string)		{newitem->string=shjson_strdup(item->string);			if (!newitem->string)		{shjson_Delete(newitem);return 0;}}
	/* If non-recursive, then we're done! */
	if (!recurse) return newitem;
	/* Walk the ->next chain for the child. */
	cptr=item->child;
	while (cptr)
	{
		newchild=shjson_Duplicate(cptr,1);		/* Duplicate (with recurse) each item in the ->next chain */
		if (!newchild) {shjson_Delete(newitem);return 0;}
		if (nptr)	{nptr->next=newchild,newchild->prev=nptr;nptr=newchild;}	/* If newitem->child already set, then crosswire ->prev and ->next and move on */
		else		{newitem->child=newchild;nptr=newchild;}					/* Set newitem->child and move to it */
		cptr=cptr->next;
	}
	return newitem;
}

void shjson_Minify(char *json)
{
	char *into=json;
	while (*json)
	{
		if (*json==' ') json++;
		else if (*json=='\t') json++;	// Whitespace characters.
		else if (*json=='\r') json++;
		else if (*json=='\n') json++;
		else if (*json=='/' && json[1]=='/')  while (*json && *json!='\n') json++;	// double-slash comments, to end of line.
		else if (*json=='/' && json[1]=='*') {while (*json && !(*json=='*' && json[1]=='/')) json++;json+=2;}	// multiline comments.
		else if (*json=='\"'){*into++=*json++;while (*json && *json!='\"'){if (*json=='\\') *into++=*json++;*into++=*json++;}*into++=*json++;} // string literals, which are \" sensitive.
		else *into++=*json++;			// All other characters.
	}
	*into=0;	// and null-terminate.
}




char *shjson_print(shjson_t *json)
{
  return (shjson_PrintUnformatted(json));
}

shjson_t *shjson_init(char *json_str)
{
  shjson_t *tree;

  if (!json_str) {
    tree = shjson_New_Item();
    tree->type = SHJSON_OBJECT;
  } else {
    tree = shjson_Parse(json_str);
  }

  return (tree);
}

shjson_t *shjson_num_add(shjson_t *tree, char *name, double num)
{
  shjson_t *node;

  if (name) {
    shjson_DeleteItemFromObject(tree, name);
  }

  node = shjson_CreateNumber(num);
  if (name)
    shjson_AddItemToObject(tree, name, node);
  else
    shjson_AddItemToArray(tree, node); 

  return (node);
}

shjson_t *shjson_null_add(shjson_t *tree, char *name)
{
  shjson_t *node;

  if (name) {
    shjson_DeleteItemFromObject(tree, name);
  }

  node = shjson_CreateNull();
  if (name) {
    shjson_AddItemToObject(tree, name, node);
  } else {
    shjson_AddItemToArray(tree, node); 
  }
  
  return (node);
}

shjson_t *shjson_array_add(shjson_t *tree, char *name)
{
  shjson_t *node;

  node = shjson_CreateArray();
  if (name)
    shjson_AddItemToObject(tree, name, node);
  else
    shjson_AddItemToArray(tree, node); 

  return (node);
}

shjson_t *shjson_obj_add(shjson_t *tree, char *name)
{
  shjson_t *node;

  node = shjson_CreateObject();
  if (name)
    shjson_AddItemToObject(tree, name, node);
  else
    shjson_AddItemToArray(tree, node); 

  return (node);
}

shjson_t *shjson_bool_add(shjson_t *tree, char *name, int val)
{
  shjson_t *node;

  if (name) {
    shjson_DeleteItemFromObject(tree, name);
  }

  node = shjson_CreateBool(val);
  if (name) {
    shjson_AddItemToObject(tree, name, node);
  } else {
    shjson_AddItemToArray(tree, node); 
  }

  return (node);
}

shjson_t *shjson_str_add(shjson_t *tree, char *name, char *val)
{
  shjson_t *node;

  if (!val)
    return (shjson_null_add(tree, name));

  if (name) {
    shjson_DeleteItemFromObject(tree, name);
  }

  node = shjson_CreateString(val);
  if (name)
    shjson_AddItemToObject(tree, name, node);
  else
    shjson_AddItemToArray(tree, node); 

  return (node);
}

void shjson_free(shjson_t **tree_p)
{
  shjson_t *tree;

  if (!tree_p)
    return;

  tree = *tree_p;
  *tree_p = NULL;

  shjson_Delete(tree);
}

char *shjson_array_astr(shjson_t *json, char *name, int idx)
{
  shjson_t *item;
  shjson_t *str_item;
  int size;
  
  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (NULL);
  } else {
    item = json;
  }

  size = shjson_GetArraySize(item);
  if (idx < 0 || idx > size)
    return (NULL);

  str_item = shjson_GetArrayItem(item, idx);
  if (!str_item || !str_item->valuestring)
    return (NULL);

  return (str_item->valuestring);
}

char *shjson_array_str(shjson_t *json, char *name, int idx)
{
  char *str;

  str = shjson_array_astr(json, name, idx);
  if (!str)
    return (NULL);

  return (strdup(str));
}

double shjson_array_num(shjson_t *json, char *name, int idx)
{
  shjson_t *item;
  shjson_t *num_item;
  double d;
  int size;
  
  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (0);
  } else {
    item = json;
  }

  size = shjson_GetArraySize(item);
  if (idx < 0 || idx > size)
    return (0);

  num_item = shjson_GetArrayItem(item, idx);
  if (!num_item)
    return (0);

  d = num_item->valuedouble;
	if (fabs(((double)num_item->valueint)-d)<=DBL_EPSILON && d<=INT_MAX && d>=INT_MIN) {
		d = (double)num_item->valueint;
	}

	return (d);
}

int shjson_array_count(shjson_t *json, char *name)
{
  shjson_t *item;
  
  if (name) {
    item = shjson_GetObjectItem(json, name);
    if (!item)
      return (0);
  } else {
    item = json;
  }

  return (shjson_GetArraySize(item));
}

shjson_t *shjson_obj_get(shjson_t *json, char *name)
{
  if (!json)
    return (NULL);
  return (shjson_GetObjectItem(json, name));
}

shjson_t *shjson_array_get(shjson_t *json, int index)
{
  if (!json)
    return (NULL);
  return (shjson_GetArrayItem(json, index));
}

void shjson_obj_append(shjson_t *item, shjson_t *obj)
{
	shjson_t *node;

	for (node = item->child; node; node = node->next) {
		switch ((node->type)&255)
		{
			case SHJSON_NULL: shjson_null_add(obj, node->string); break;

			case SHJSON_FALSE:
				shjson_bool_add(obj, node->string, FALSE); 
				break;

			case SHJSON_TRUE: shjson_bool_add(obj, node->string, TRUE); break;

			case SHJSON_NUMBER: 
				shjson_num_add(obj, node->string, shjson_num(node, NULL, 0)); 
				break;

			case SHJSON_STRING: 
				shjson_str_add(obj, node->string, shjson_str(node, NULL, "")); 
				break;

			case SHJSON_ARRAY:
				shjson_obj_append(node, shjson_array_add(obj, node->string));
				break;

			case SHJSON_OBJECT:
				shjson_obj_append(node, shjson_obj_add(obj, node->string));
				break;
		}
	}

}



