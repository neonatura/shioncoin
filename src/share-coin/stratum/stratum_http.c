
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
			if (idx == TESTNET_COIN_IFACE) continue;
			if (idx == COLOR_COIN_IFACE) continue;
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
    if (nIdx == 0 || nIdx == TESTNET_COIN_IFACE || nIdx == COLOR_COIN_IFACE) continue;

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

    if (json)
      height = shjson_array_num(json, "result", 0);

    shbuf_catstr(buff,
        "<div style=\"font-size : 14px; font-family : Georgia; height : 32px; width : 99%; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; padding-top : 10px;\">\r\n"); 


    /* pulldown in order to traverse to other shcoind stratum http pages */
    shbuf_catstr(buff,
        "<div style=\"float : right; margin-right : 16px;\">\r\n"
        "<select onchange=\"window.location.href=this.options[this.selectedIndex].value;\" style=\"font-variant : small-caps; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 9px; border : 0; -webkit-appearance : none; -moz-appearance : none; text-indent: 0.01px; text-overflow: ''; overflow : none;\">\r\n");

    shbuf_catstr(buff, "<option selected disabled value=\" \" style=\"color : #666; outline : 0;\"> </option>");
    for (t_sk = 1; t_sk < get_max_descriptors(); t_sk++) {
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
          "<div style=\"float : left; margin-left : 16px; font-size : 12px;\">Block Height: %lu</div>\r\n"
          "<div style=\"float : left; margin-left : 16px; font-size : 12px;\">Difficulty: %-4.4f</div>\r\n"
          "<div style=\"float : left; margin-left : 16px; font-size : 12px;\">Global Speed: %-3.3fmh/s</div>\r\n"
          "<div style=\"float : left; margin-left : 16px; font-size : 12px;\">Max Coins: %lu</div>\r\n"
          "<div style=\"float : left; margin-left : 16px; font-size : 12px;\">Mined Coins: %-1.1f/sec</div>\r\n"
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
    validate_render_fractal(SHC_COIN_IFACE, bmp_path, zoom, span, x_of, y_of);
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
  double shares;
  double speed;
  int i;

  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++) {
      shares += user->block_avg[i];
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
      "<div style=\"float : right; margin-top : 8px; margin-right : 8px;\">\n");
  sprintf(ret_html,
      "<div style=\"margin-top : 4px; margin-right : 64px; float : right; font-size : 11px; width : 100px; background-color : #ddd;\">%-1.1f shares/sec</div>\n"
      "<div style=\"margin-top : 4px; margin-right : 64px; float : right; font-size : 11px; width : 100px; background-color : #ddd;\">%-1.1f hashes/sec</div>\n"
"</div><div style=\"clear : both;\"></div>"

,
      (shares/3600), (speed/3600));
  shbuf_catstr(buff, ret_html);

  if (ifaceIndex != SHC_COIN_IFACE)
    return;

  shbuf_catstr(buff,
      "<div style=\"float : right; height : 15px; transform : rotate(270deg); margin-top : 64px; margin-left : -22px;\"><span style=\"font-size : 11px; font-variant : small-caps;\">Validation Matrix</span></div>\n"
      "<div style=\"float : right;\"><img id=\"validate_matrix_img\" name=\"validate_matrix_img\" src=\"/image/validate_matrix.bmp?span=0.5&x=128&y=128\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin-top : 18px;\"></div>\n");

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

  stratum_http_block_html(ifaceIndex, buff); 

  shbuf_catstr(buff, 
      "<div style=\"margin-left : 64px; float : left; width : 60%; font-size : 13px;\">" 
      "<table cellspacing=2 style=\"width : 100%; linear-gradient(to bottom, #1e9957,#29d889,#20ca7c,#8de8b9); color : #666;\">"
      "<tr style=\"background-color : rgba(128,128,128,0.5); color : #eee;\"><td>Worker</td><td>Speed</td><td>Shares</td><td>Blocks</td></tr>");
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


http_t http_table[] = {
	{ "/coin/", MIME_HTML, 
		http_coin_content, http_coin_blurb },

	{ "/pool/", MIME_HTML, 
		http_pool_content, http_pool_blurb },

	{ "/spring/", MIME_HTML,
		http_matrix_spring_content, http_matrix_spring_blurb },

	{ "/validate/", MIME_HTML,
		http_matrix_validate_content, http_matrix_validate_blurb },

	{ "/alias/", MIME_HTML,
		http_alias_content, http_alias_blurb },

	{ "/context/", MIME_HTML,
		http_context_content, http_context_blurb },

	{ "/i/spring.bmp", MIME_BMP, http_fractal_spring_cb },
	{ "/i/validate.bmp", MIME_BMP, http_fractal_validate_cb },


	{ NULL, NULL }
};

void stratum_html_header(shbuf_t *buff)
{

	shbuf_catstr(buff, "<div class=\"header\">\r\n"); 

#if 0
	shbuf_catstr(buff, 
			"<div style=\"float : right;\">\r\n"
			"<img src=\"data:image/png;base64,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\" />\r\n"
			"</div>\r\n"
			);
#endif

	shbuf_catstr(buff, 
			"<div style=\"float : left;\">\r\n"
			"<img src=\"data:image/png;base64,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\" />\r\n"
			"</div>\r\n"
			);

	shbuf_catstr(buff,
			"<div style=\"float : left;\">\r\n"
			"<span style=\"font-size : 24px;\">ShareCoin Daemon</span>\r\n"
			"</div>\r\n");

	shbuf_catstr(buff, "</div>\r\n"); /* /header */

}

shbuf_t *stratum_html_content(httpreq_t *req)
{
	shbuf_t *buff;

	buff = shbuf_init();
	req->buff = buff;

	if (req->h->mime == MIME_HTML) {
		shbuf_catstr(buff,
				"<!DOCTYPE html>\r\n"
				"<html lang=\"en\">\r\n");

		shbuf_catstr(buff, 
				"<head>\r\n"
				"<style type=\"text/css\">\r\n"
				".box { margin-left : auto; margin-right : auto; font-size: 16px; min-height: 200px; overflow: hidden; width : 98%; z-index: 1; border-radius: 2px; box-sizing: border-box; background : linear-gradient(90deg, #4b6cb7 0%, #182848 100%); float : left; text-decoration : none; }\r\n"
				".item { height: 32px; line-height: 32px; padding: 0 12px 0 12px; border: 0; border-radius: 6px; background-color: rgba(222,222,222,0.5); color: rgba(0,0,0,.87); white-space: nowrap; width : auto; margin-top : 16px; margin-bottom : 16px; margin-left : 2px; margin-right : 2px; text-align : center; }\r\n"
				".title { float : left; color : #dedede; background : rgba(0,0,0,.3); line-height : 16px; border-radius : 6px; padding : 1px 3px 1px 3px; text-decoration : underline; margin-top : -14px; }\r\n"
				".value { clear : both; }\r\n"
				".list { width : 100%; linear-gradient(to bottom, #1e9957,#29d889,#20ca7c,#8de8b9); color : #666; }\r\n"
				".listheader { display : none; }\r\n"
				"\r\n"
				"</style>\r\n"
				"</head>\r\n"); 

		shbuf_catstr(buff, "<body>\r\n"); 

		/* header */
		stratum_html_header(buff);

		shbuf_catstr(buff, "<div class=\"box\">\r\n");
	}

	if (req->h->f_content) {
		(*req->h->f_content)(req);
	} else if (req->h->f_blurb) {
		(*req->h->f_blurb)(req);
	}

	if (req->h->mime == MIME_HTML) {
		shbuf_catstr(buff, "</div>");
		shbuf_catstr(buff, "</body></html>\r\n");
	}

	return (buff);
}

/* main index page -- shows blurbs */
shbuf_t *stratum_html_main_content(struct httpreq_t *req)
{
	shbuf_t *buff;
	char html[1024];
	int idx;

	buff = shbuf_init();

	shbuf_catstr(buff,
			"<!DOCTYPE html>\r\n"
			"<html lang=\"en\">\r\n");

	shbuf_catstr(buff, 
			"<head>\r\n"
			"<style type=\"text/css\">\r\n"
			".box { margin : 1em 1em 1em 1em; font-size: 16px; min-height: 280px; overflow: hidden; width: 342px; z-index: 1; border-radius: 2px; box-sizing: border-box; background : linear-gradient(90deg, #4b6cb7 0%, #182848 100%); float : left; text-decoration : none; border-right : 1px solid #ccc; border-bottom : 1px solid #ccc; }\r\n"
			".item { height: 32px; line-height: 32px; padding: 0 12px 0 12px; border: 0; border-radius: 6px; background-color: rgba(222,222,222,0.5); color: rgba(0,0,0,.87); font-size: 12px; white-space: nowrap; width : auto; text-align : center; min-width : 64px; }\r\n"
			".title { display : none; }\r\n"
			".value { clear : both; }\r\n"
			".list { width : 100%; linear-gradient(to bottom, #1e9957,#29d889,#20ca7c,#8de8b9); color : #666; }\r\n"
			".listheader { background-color : rgba(128,128,128,0.5); color : #eee; text-align : center; }\r\n"
			"</style>\r\n"
			"</head>\r\n"); 

	shbuf_catstr(buff, "<body>\r\n"); 

	req->buff = buff;
	for (idx = 0; http_table[idx].page; idx++) {
		if (http_table[idx].f_blurb) {
			sprintf(html, "<a href=\"%s\" class=\"boxlink\">\r\n", 
					http_table[idx].page);
			shbuf_catstr(buff, html);

			/* blurb content */
			shbuf_catstr(buff, "<div class=\"box\">\r\n");
			(*http_table[idx].f_blurb)(req);
			shbuf_catstr(buff, "</div>");

			shbuf_catstr(buff, "</a>\r\n");
		}
	}

	shbuf_catstr(buff, "</body></html>\r\n");

	return (buff);
}

void stratum_http_header(http_t *h, shbuf_t *buff, size_t data_len)
{
	char str[1024];

	shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 

	sprintf(str, "Content-Type: %s\r\n", h->mime);
	shbuf_catstr(buff, str);

	sprintf(str, "Content-Length: %u\r\n", (unsigned int)data_len);
	shbuf_catstr(buff, str);

	shbuf_catstr(buff, "\r\n"); 
}

static int ctype_digit(const char *str)
{
	int i;

	i = 0;
	if (str[0] == '-')
		i++;

	for (i = 0; i < strlen(str); i++) {
		if (!isdigit(str[i]) && str[i] != '.')
			return (FALSE);
	}

	return (TRUE);
}

static shjson_t *stratum_http_args(char *url, char *ret_url)
{
	shjson_t *args;
	char *tok;
	char *value;
	char name[1024];
	int idx;

	args = shjson_init(NULL);

	idx = stridx(url, '?');
	if (idx == -1) {
		strcpy(ret_url, url);
		return (args);
	}

	strncpy(ret_url, url, idx);
	ret_url[idx] = '\000';

	tok = strtok(url + (idx + 1), "&");
	while (tok) {

		idx = stridx(tok, '=');
		if (idx == -1) {
			tok = strtok(NULL, "&");
			continue;
		}

		memset(name, 0, sizeof(name));
		strncpy(name, tok, idx); 
		value = (tok + (idx + 1));

		if (*name) {
			if (ctype_digit(value))
				shjson_num_add(args, name, atof(value));
			else
				shjson_str_add(args, name, value);
		}

		tok = strtok(NULL, "&");
	}

	return (args);
}

int stratum_http_call(const char *url, shbuf_t *buff)
{
	struct httpreq_t req;
	shbuf_t *cbuff;
	shjson_t *args = NULL;
	char base_url[4096];
	int i;

	args = stratum_http_args(url, base_url);
fprintf(stderr, "DEBUG: stratum_http_call: '%s' (%s)_\n", base_url, url);

	if (0 == strcmp(base_url, "/")) {
		struct http_t h;

		/* html header */
		memset(&h, 0, sizeof(h));
		h.mime = MIME_HTML;
		h.page = "/";

		memset(&req, 0, sizeof(req));
		req.h = &h;
		req.buff = buff;
		req.args = args;

		cbuff = stratum_html_main_content(&req);

		stratum_http_header(&h, buff, shbuf_size(cbuff));
	} else {
		for (i = 0; http_table[i].page; i++) {
			if (0 == strcasecmp(base_url, http_table[i].page))
				break;
		}
		if (!http_table[i].page)
			return (ERR_AGAIN);

		/* generate content */
		memset(&req, 0, sizeof(req));
		req.h = (http_table + i);
		req.buff = buff;
		req.args = args;
		cbuff = stratum_html_content(&req);

		/* html header */
		stratum_http_header(http_table + i, buff, shbuf_size(cbuff));
	}

	/* html content */
  shbuf_append(cbuff, buff);

	shbuf_free(&cbuff);
	shjson_free(&args);

	return (0);
}

void stratum_http_request(unsigned int sk, char *url)
{
  user_t *user;
  shbuf_t *buff;
  char ret_html[4096];
  int ifaceIndex;
	int err;

  buff = shbuf_init();

	err = stratum_http_call(url, buff);
	if (!err) {
    unet_write(sk, shbuf_data(buff), shbuf_size(buff));
    shbuf_free(&buff);
    unet_shutdown(sk);
	}

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
