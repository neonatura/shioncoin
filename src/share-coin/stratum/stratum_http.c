
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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

#include "shcoind.h"
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"

static const char *_stratum_user_html_template = 
"\r\n"
"Name: %s\r\n"
"Speed: %f\r\n"
"Shares: %lu\r\n"
"Accepted: %u\r\n"
"\r\n";

static double get_avg_balance(int ifaceIndex)
{
  user_t *user;
  double balance;

  if (ifaceIndex <= 0 || ifaceIndex > MAX_COIN_IFACE)
    return (0.0);

  balance = 0.0;
  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    balance += user->balance_avg[ifaceIndex];
  }

  return (balance);
}

char *stratum_http_response(unsigned int sk, char *url, int *idx_p)
{
  static shbuf_t *buff; 
  char html[10240];
  char uname[512];
char ip_addr[MAXHOSTNAMELEN+1]; 
  int idx;
int t_sk;
unet_table_t *t;

  if (!buff)
    buff = shbuf_init();
  shbuf_clear(buff);

  CIface *iface = NULL;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx);
    if (0 == strncmp(url+1, iface->name, strlen(iface->name)))
      break;
  }
  if (idx == MAX_COIN_IFACE) {
    for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
      iface = GetCoinByIndex(idx);
      if (iface && iface->enabled)
        break;
    }
  }
  if (idx_p)
    *idx_p = idx;

  int next_idx;
  CIface *next_iface = NULL;
  for (next_idx = 1; next_idx < MAX_COIN_IFACE; next_idx++) {
    int nIdx = (idx + next_idx) % MAX_COIN_IFACE;
    if (nIdx == 0) continue;

    next_iface = GetCoinByIndex(nIdx);
    if (next_iface && next_iface->enabled)
      break;
  }
  if (next_idx == MAX_COIN_IFACE)
    next_iface = NULL;

  {
    const char *json_str = getmininginfo(idx);
    shjson_t *json = shjson_init(json_str);
    unsigned long height = 0;

if (!json) {
fprintf(stderr, "DEBUG: stratum_http_request: NULL json for idx #%d: %s\n", idx, json_str);
}

    if (json)
      height = shjson_array_num(json, "result", 0);

    shbuf_catstr(buff,
        "<div style=\"font-size : 14px; font-family : Georgia; height : 32px; width : 99%; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; padding-top : 10px;\">\r\n"); 


    /* pulldown in order to traverse to other shcoind stratum http pages */
    shbuf_catstr(buff,
        "<div style=\"float : right; margin-right : 16px;\">\r\n"
        "<select onchange=\"window.location.href=this.options[this.selectedIndex].value;\" style=\"font-variant : small-caps; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 9px; border : 0; -webkit-appearance : none; -moz-appearance : none; text-indent: 0.01px; text-overflow: ''; overflow : none;\">\r\n");

    shbuf_catstr(buff, "<option selected disabled value=\" \" style=\"color : #666; outline : 0;\"> </option>");
    for (t_sk = 1; t_sk < MAX_UNET_SOCKETS; t_sk++) {
      t = get_unet_table(t_sk);
      if (!t)
        continue; /* non-active */
      if (t->mode != SHC_COIN_IFACE)
        continue; /* irrelevant */
      if (!(t->flag & DF_SERVICE))
        continue; /* irrelevant */

      memset(ip_addr, 0, sizeof(ip_addr));
      strncpy(ip_addr, shaddr_print(&t->net_addr), sizeof(ip_addr)-1);
      strtok(ip_addr, ":");
      sprintf(html, "<option value=\"http://%s:9448/\" style=\"color : #666; outline : 0;\">%s</option>", ip_addr, ip_addr); 
      shbuf_catstr(buff, html);
    }
    shbuf_catstr(buff,
        "</select>\n"
        "</div>\n");


    if (next_iface) {
      sprintf(html,
          "<div style=\"float : right; margin-right : 16px; padding-left : 1px; padding-right : 1px;\">\n"
          "<form><input type=\"submit\" value=\"%s\" style=\"font-variant : small-caps; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 9px; border : 0; outline : 0; padding-left : 1px; padding-right : 1px;\" onclick=\"window.location.href='/%s/';return false;\"></form>\n"
          "</div>\n",
          next_iface->name, next_iface->name);
      shbuf_catstr(buff, html);
    }

    if (json) {
      sprintf(html,
          "<div style=\"float : left; margin-left : 16px; margin-right : 16px; font-size : 16px;\">%s</div>\r\n"
          "<div style=\"float : left; margin-left : 16px;\">Block Height: %lu</div>\r\n"
          "<div style=\"float : left; margin-left : 16px;\">Difficulty: %-4.4f</div>\r\n"
          "<div style=\"float : left; margin-left : 16px;\">Global Speed: %-3.3fmh/s</div>\r\n"
          "<div style=\"float : left; margin-left : 16px;\">Max Coins: %lu</div>\r\n"
          "<div style=\"float : left; margin-left : 16px;\">Mined Coins: %-1.1f/sec</div>\r\n"
          "<div style=\"clear : both;\"></div>\r\n"
          "</div>\r\n"
          "<hr></hr>\r\n",
          iface->name, height,
          shjson_array_num(json, "result", 1),
          shjson_array_num(json, "result", 2) / 1000000,
          (unsigned long)(iface->max_money / COIN),
          get_avg_balance(GetCoinIndex(iface)));
      shbuf_catstr(buff, html);
      shjson_free(&json);
    }

/* DEBUG: TODO: .. show mem usage .. blockIndex vs mapped files ~ */
  }

  return (shbuf_data(buff));
}

void stratum_http_spring_img_html(shbuf_t *buff)
{

  shbuf_catstr(buff,
      "<div style=\"margin-top : 64px; height : 0px;\"></div>\n"
      "\n"
      "<div style=\"width : 256px; margin-left : auto; margin-right : auto;\">\n"
      "<div style=\"float : right; margin-right : 32px;\"> <span>Spring Matrix</span> </div>\n"
      "<div style=\"float : left; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\">\n"
      "<span id=\"spring_matrix_lbl\">x1</span>\n"
      "</div>\n"
      /* expand */
      "<div style=\"float : left; margin-left : 16px; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\"><a href=\"/image/spring_matrix.bmp?span=0.1&x=128&y=128\" id=\"spring_matrix_ref\"><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+AHFRcvLtjUSsgAAAGqSURBVEhL5ZVBbtRAEEV/VTViMXcB5QZhzwoWSGEBEkJwBKJIiZBAuUOEFNYBzgA3AImDsMoiyL8+i3TPmLGNx4Edb9N2d5W/67e7DOyIpBNtOJmLb/hcwN+ySEDSXMiARQJmNhcyYJHATVgk8E8syszfxj5TFpEEMJ4zEHB3kHzgvntxEQGSD8dy1jNd1wEASD4D8GkQiVmLPpJ8DmwqAnoC7r4i+drM3k1YIWAtMlAyM5jZGck3ZrZq8wUASN6VdO7uezXZJL0CcLvGCcB+T3i/CrWJqxZnZkeZeZ/k04j4BpIHJK8yU5KytoI2bpMza9cXmSL5k+TjUqtob7L8JG2huk+12lsGACT3ALx39zuoFgE4xJZFAO7V+88AvqBnkaRTM5Mkk/QdwJOI+IpGZq5Ivs1MZeZgEyUd9+w4HllXzT3tum69yeuvSNJlRBxJeqHxz7Fv38DKzISkl+5+6O6Xbb60i4ho4xnJH9sPmEPSo1LKBXB9WBujrSIiPvQPS2OiMpBEKeViLGe0VQCbivpM9aJe9YO13RvODVkkMGXRn1gk8H/+0X4B9mM0rhW8WLcAAAAASUVORK5CYII=\" style=\"width : 15px; height : 15px;\" alt=\"Expand Image\"></a></div>\n"
      "<div style=\"clear : both;\"></div>\n"
      "<hr style=\"width : 80%;\">\n"
      "<div id=\"spring_matrix\" name=\"spring_matrix\" style=\"width : 256px; height : 256px; padding : 0 0 0 0; margin : 0 0 0 0; border : 0;\" onclick=\"matrixClick(this)\">\n"
      "<img id=\"spring_matrix_img\" name=\"spring_matrix_img\" src=\"\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\">\n"
      "</div>\n"
      "</div>\n");


  shbuf_catstr(buff,
      "<script type=\"text/javascript\">\n"
      "document.getElementById(\"spring_matrix\").addEventListener(\"click\", clickPos, false);\n"
      "var offsetX = 0.0;\n"
      "var offsetY = 0.0;\n"
      "var mSpringClick = false;\n"
      "var mValidateClick = false;\n"
      "var zoom = 0.0;\n"
      "var clientX = 0.0;\n"
      "var clientY = 0.0;\n"
      "function matrixClick(el) {\n"
      "  offsetX = el.offsetLeft;\n"
      "  offsetY = el.offsetTop;\n"
      "  mSpringClick = true;\n"
      "  return false;\n"
      "}\n"
      "function clickPos(e) {\n"
      "  if (zoom == 0.5) {\n"
      "    clientX = e.clientX;\n"
      "    clientY = e.clientY;\n"
      "  }\n"
      "  printMatrix();\n"
      "}\n"
      "function printMatrix(e)\n"
      "{\n"
      "  var i = null, l = null;\n"
      "  if (mSpringClick) {\n"
      "    i = document.getElementById(\"spring_matrix_img\");\n"
      "    l = document.getElementById(\"spring_matrix_lbl\");\n"
      "  } else if (mValidateClick) {\n"
      "    i = document.getElementById(\"validate_matrix_img\");\n"
      "    l = document.getElementById(\"validate_matrix_lbl\");\n"
      "  }\n"
      "  mSpringClick = false;\n"
      "  mValidateClick = false;\n"
      "  if (i == null || l == null)\n"
      "    return;\n"
      "\n"
      "  var srcX = clientX - offsetX;\n"
      "  var srcY = clientY - offsetY;\n"
      "  i.src = \"/image/spring_matrix.bmp?y=\" + srcY + \"&x=\" + srcX + \"&zoom=\" + zoom;\n"
      "  l.innerHTML = \"x\" + (1 / zoom);\n"
      "\n"
      "  if (zoom < 0.001) {\n"
      "    zoom = 1.0;\n"
      "    clientX = offsetX + 128.0;\n"
      "    clientY = offsetY + 128.0;\n"
      "  } else {\n"
      "    zoom /= 2;\n"
      "  }\n"
      "\n"
      "}\n"
      "function initMatrix()\n"
      "{\n"
      "  zoom = 1.0;\n"
      "  offsetX = 0.0;\n"
      "  offsetY = 0.0;\n"
      "  clientX = 128.0;\n"
      "  clientY = 128.0;\n"
      "}\n"
      "initMatrix();\n"
      "mSpringClick = true;\n"
      "printMatrix();\n"
      "</script>\n"
      );

}

void stratum_http_validate_img_html(shbuf_t *buff)
{

  shbuf_catstr(buff,
      "<div style=\"margin-top : 64px; height : 0px;\"></div>\n"
      "\n"
      "<div style=\"width : 256px; margin-left : auto; margin-right : auto;\">\n"
      "<div style=\"float : right; margin-right : 32px;\"> <span>Validate Matrix</span> </div>\n"
      "<div style=\"float : left; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\">\n"
      "<span id=\"validate_matrix_lbl\">x1</span>\n"
      "</div>\n"
      /* expand */
      "<div style=\"float : left; margin-left : 16px; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\"><a href=\"/image/validate_matrix.bmp?span=0.1&x=128&y=128\" id=\"validate_matrix_ref\"><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+AHFRcvLtjUSsgAAAGqSURBVEhL5ZVBbtRAEEV/VTViMXcB5QZhzwoWSGEBEkJwBKJIiZBAuUOEFNYBzgA3AImDsMoiyL8+i3TPmLGNx4Edb9N2d5W/67e7DOyIpBNtOJmLb/hcwN+ySEDSXMiARQJmNhcyYJHATVgk8E8syszfxj5TFpEEMJ4zEHB3kHzgvntxEQGSD8dy1jNd1wEASD4D8GkQiVmLPpJ8DmwqAnoC7r4i+drM3k1YIWAtMlAyM5jZGck3ZrZq8wUASN6VdO7uezXZJL0CcLvGCcB+T3i/CrWJqxZnZkeZeZ/k04j4BpIHJK8yU5KytoI2bpMza9cXmSL5k+TjUqtob7L8JG2huk+12lsGACT3ALx39zuoFgE4xJZFAO7V+88AvqBnkaRTM5Mkk/QdwJOI+IpGZq5Ivs1MZeZgEyUd9+w4HllXzT3tum69yeuvSNJlRBxJeqHxz7Fv38DKzISkl+5+6O6Xbb60i4ho4xnJH9sPmEPSo1LKBXB9WBujrSIiPvQPS2OiMpBEKeViLGe0VQCbivpM9aJe9YO13RvODVkkMGXRn1gk8H/+0X4B9mM0rhW8WLcAAAAASUVORK5CYII=\" style=\"width : 15px; height : 15px;\" alt=\"Expand Image\"></a></div>\n"
      "<div style=\"clear : both;\"></div>\n"
      "<hr style=\"width : 80%;\">\n"
      "<div id=\"validate_matrix\" name=\"validate_matrix\" style=\"width : 256px; height : 256px; padding : 0 0 0 0; margin : 0 0 0 0; border : 0;\" onclick=\"matrixClick(this)\">\n"
      "<img id=\"validate_matrix_img\" name=\"validate_matrix_img\" src=\"\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\">\n"
      "</div>\n"
      "</div>\n");


  shbuf_catstr(buff,
      "<script type=\"text/javascript\">\n"
      "document.getElementById(\"validate_matrix\").addEventListener(\"click\", clickPos, false);\n"
      "var offsetX = 0.0;\n"
      "var offsetY = 0.0;\n"
      "var mValidateClick = false;\n"
      "var zoom = 0.0;\n"
      "var clientX = 0.0;\n"
      "var clientY = 0.0;\n"
      "function matrixClick(el) {\n"
      "  offsetX = el.offsetLeft;\n"
      "  offsetY = el.offsetTop;\n"
      "  mValidateClick = true;\n"
      "  return false;\n"
      "}\n"
      "function clickPos(e) {\n"
      "  if (zoom == 0.5) {\n"
      "    clientX = e.clientX;\n"
      "    clientY = e.clientY;\n"
      "  }\n"
      "  printMatrix();\n"
      "}\n"
      "function printMatrix(e)\n"
      "{\n"
      "  var i = null, l = null;\n"
      "  if (mValidateClick) {\n"
      "    i = document.getElementById(\"validate_matrix_img\");\n"
      "    l = document.getElementById(\"validate_matrix_lbl\");\n"
      "  }\n"
      "  mValidateClick = false;\n"
      "  if (i == null || l == null)\n"
      "    return;\n"
      "\n"
      "  var srcX = clientX - offsetX;\n"
      "  var srcY = clientY - offsetY;\n"
      "  i.src = \"/image/validate_matrix.bmp?y=\" + srcY + \"&x=\" + srcX + \"&zoom=\" + zoom;\n"
      "  l.innerHTML = \"x\" + (1 / zoom);\n"
      "\n"
      "  if (zoom < 0.001) {\n"
      "    zoom = 1.0;\n"
      "    clientX = offsetX + 128.0;\n"
      "    clientY = offsetY + 128.0;\n"
      "  } else {\n"
      "    zoom /= 2;\n"
      "  }\n"
      "\n"
      "}\n"
      "function initMatrix()\n"
      "{\n"
      "  zoom = 1.0;\n"
      "  offsetX = 0.0;\n"
      "  offsetY = 0.0;\n"
      "  clientX = 128.0;\n"
      "  clientY = 128.0;\n"
      "}\n"
      "initMatrix();\n"
      "mValidateClick = true;\n"
      "printMatrix();\n"
      "</script>\n"
      );

}

void stratum_http_spring_img(char *args, shbuf_t *buff)
{
  FILE *fl;
  struct stat st;
  double x_of, y_of, zoom;
  double span;
  char *bmp_path;
  char tag[256];
  char *data;
  char str[256];
  char *ptr;
  int err;

  zoom = 1.0;
  ptr = strstr(args, "zoom=");
  if (ptr)
    zoom = atof(ptr+5);

  x_of = 0;
  ptr = strstr(args, "x=");
  if (ptr)
    x_of = atof(ptr+2);

  y_of = 0;
  ptr = strstr(args, "y=");
  if (ptr)
    y_of = atoi(ptr+2);

  span = 1.0;
  ptr = strstr(args, "span=");
  if (ptr)
    span = atof(ptr+5);
  span = MAX(0.2, span);

  x_of = floor(x_of / 8) * 8;
  y_of = floor(y_of / 8) * 8;

  sprintf(tag, "spring_bmp:%f,%f,%f,%f", zoom, span, x_of, y_of);
  bmp_path = shcache_path(tag);
  if (!shcache_fresh(tag))
    spring_render_fractal(bmp_path, zoom, span, x_of, y_of);
  stat(bmp_path, &st);

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: image/bmp\r\n");
  sprintf(str, "Content-Length: %u\r\n", st.st_size);
  shbuf_catstr(buff, str);
  shbuf_catstr(buff, "\r\n"); 

  err = shfs_mem_read(bmp_path, buff);
#if 0
  data = (char *)calloc(st.st_size, sizeof(char));
  fl = fopen(bmp_path, "rb");
  fread(data, sizeof(char), st.st_size, fl);
  fclose(fl);
  shbuf_cat(buff, data, st.st_size); 
  free(data);
#endif
}

void stratum_http_validate_img(char *args, shbuf_t *buff)
{
  FILE *fl;
  struct stat st;
  double x_of, y_of, zoom;
  double span;
  char *bmp_path;
  char tag[256];
  char *data;
  char str[256];
  char *ptr;
  int err;

  zoom = 1.0;
  ptr = strstr(args, "zoom=");
  if (ptr)
    zoom = atof(ptr+5);

  x_of = 0;
  ptr = strstr(args, "x=");
  if (ptr)
    x_of = atof(ptr+2);

  y_of = 0;
  ptr = strstr(args, "y=");
  if (ptr)
    y_of = atoi(ptr+2);

  span = 1.0;
  ptr = strstr(args, "span=");
  if (ptr)
    span = atof(ptr+5);
  span = MAX(0.2, span);

  x_of = floor(x_of);
  y_of = floor(y_of);

  sprintf(tag, "validate_bmp:%f,%f,%f,%f", zoom, span, x_of, y_of);
  bmp_path = shcache_path(tag);
  if (!shcache_fresh(tag))
    validate_render_fractal(bmp_path, zoom, span, x_of, y_of);
  stat(bmp_path, &st);

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: image/bmp\r\n");
  sprintf(str, "Content-Length: %u\r\n", st.st_size);
  shbuf_catstr(buff, str);
  shbuf_catstr(buff, "\r\n"); 

  err = shfs_mem_read(bmp_path, buff);
#if 0
  data = (char *)calloc(st.st_size, sizeof(char));
  fl = fopen("/tmp/validate_fractal.bmp", "rb");
  fread(data, sizeof(char), st.st_size, fl);
  fclose(fl);
  shbuf_cat(buff, data, st.st_size); 
  free(data);
#endif
}


void stratum_http_block_html(int ifaceIndex, shbuf_t *buff)
{
  user_t *user;
  char ret_html[1024];
#if 0
  char mine[256];
#endif
  double rounds;
  double speed;
  int i;

  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++) {
      rounds += user->block_avg[i];
    }
    speed = stratum_user_speed(user);
  }

#if 0
  memset(mine, 0, sizeof(mine));
  {
    CIface *mine_iface = GetCoinByIndex(DefaultWorkIndex);
    if (mine_iface)
      strncpy(mine, mine_iface->name, sizeof(mine)-1);
  }
#endif


  shbuf_catstr(buff,
      "<div style=\"float : right; height : 15px; transform : rotate(270deg);\"><span style=\"font-size : 11px; font-variant : small-caps;\">Validation Matrix</span></div>\n"
      "<div style=\"float : right;\"><img id=\"validate_matrix_img\" name=\"validate_matrix_img\" src=\"/image/validate_matrix.bmp?span=1.0&x=128&y=128\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\"></div>\n"
      "<div style=\"clear : right; margin-top : 4px;\">\n");
  sprintf(ret_html,
//      "<div style=\"margin-top : 4px; margin-right : 32px; float : right; font-size : 11px; width : 90px; background-color : #ddd;\">mining: %s</div>\n"
      "<div style=\"margin-top : 4px; margin-right : 32px; float : right; font-size : 11px; width : 90px; background-color : #ddd;\">%-1.1f shares/sec</div>\n"
      "<div style=\"margin-top : 4px; margin-right : 32px; float : right; font-size : 11px; width : 90px; background-color : #ddd;\">%-1.1f hashes/sec</div>\n",
//      mine,
 (rounds/3600), (speed/3600));
  shbuf_catstr(buff, ret_html);

}

#define SPRING_MATRIX_HTML "/spring/"
#define SPRING_MATRIX_BMP "/image/spring_matrix.bmp"
#define VALIDATE_MATRIX_BMP "/image/validate_matrix.bmp"
void stratum_http_main_html(unsigned int sk, char *url, shbuf_t *buff)
{
  user_t *user;
  char ret_html[4096];
  int ifaceIndex;

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: text/html\r\n");
  shbuf_catstr(buff, "\r\n"); 
  shbuf_catstr(buff, "<html><body>\r\n"); 
  shbuf_catstr(buff, stratum_http_response(sk, url, &ifaceIndex));

  shbuf_catstr(buff, "<div style=\"clear : both;\"></div>");

  shbuf_catstr(buff, 
      "<div style=\"width : 80%; margin-left : auto; margin-right : auto; font-size : 13px; width : 90%;\">" 
      "<table cellspacing=1 style=\"width : 100%; linear-gradient(to bottom, #1e9957,#29d889,#20ca7c,#8de8b9); color : #666;\">"
      "<tr style=\"background-color : lime; color : #999;\"><td>Worker</td><td>Speed</td><td>Shares</td><td>Blocks Submitted</td></tr>");
  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    sprintf(ret_html,
        "<tr><td>%s</td>"
        "<td>%-2.2f</td>"
        "<td>%-8.8f</td>"
        "<td>%u</td></tr>",
        user->worker, stratum_user_speed(user),
        user->block_tot, (unsigned int)user->block_cnt);
    shbuf_catstr(buff, ret_html);
  }
  shbuf_catstr(buff, "</table>\r\n");


  stratum_http_block_html(ifaceIndex, buff); 

#if 0
  if (ifaceIndex == SHC_COIN_IFACE) {
    /* attach image of the SHC validation matrix */
    stratum_http_validate_img_html(buff);
  }
#endif

  shbuf_catstr(buff, "</div>\r\n");
  shbuf_catstr(buff, "</body></html>\r\n"); 

}

void stratum_http_spring_html(unsigned int sk, char *url, shbuf_t *buff)
{
  int ifaceIndex;

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: text/html\r\n");
  shbuf_catstr(buff, "\r\n"); 
  shbuf_catstr(buff, "<html><body>\r\n"); 
  shbuf_catstr(buff, stratum_http_response(sk, url, &ifaceIndex));

  /* attach image of current spring matrix fractal */
  stratum_http_spring_img_html(buff);

}

void stratum_http_request(unsigned int sk, char *url)
{
  user_t *user;
  shbuf_t *buff;
  char ret_html[4096];
  int ifaceIndex;

  buff = shbuf_init();

  if (0 == strncmp(url, SPRING_MATRIX_BMP, strlen(SPRING_MATRIX_BMP))) {
    stratum_http_spring_img(url + strlen(SPRING_MATRIX_BMP), buff);
    unet_write(sk, shbuf_data(buff), shbuf_size(buff));
    shbuf_free(&buff);
    unet_shutdown(sk);
    return;
  }
  if (0 == strncmp(url, VALIDATE_MATRIX_BMP, strlen(VALIDATE_MATRIX_BMP))) {
    stratum_http_validate_img(url + strlen(VALIDATE_MATRIX_BMP), buff);
  } else if (0 == strncmp(url, SPRING_MATRIX_HTML, strlen(SPRING_MATRIX_HTML))) {
    stratum_http_spring_html(sk, url, buff);
  } else {
    stratum_http_main_html(sk, url, buff);
  }

  unet_write(sk, shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);

  unet_shutdown(sk);
}
