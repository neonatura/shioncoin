
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "stratum/stratum.h"
#include <math.h>
#include "coin_proto.h"


void http_matrix_blurb(httpreq_t *req, const char *tag)
{
	shbuf_t *buff = req->buff;
	char html[4096];
	char label[256];

	memset(label, 0, sizeof(label));
	strncpy(label, tag, sizeof(label));
	label[0] = toupper(label[0]);

#if 0
	sprintf(html,
			"<div style=\"width : 256px; margin-left : auto; margin-right : auto;\">\n"
			"<div style=\"width : 120px; margin-left : auto; margin-right : auto;;\"><span style=\"color : #333;\">%s Matrix</span> </div>\n"
			"</div>\n",
			label);
	shbuf_catstr(buff, html);
#endif

	sprintf(html,
      "<div id=\"%s_matrix\" name=\"%s_matrix\" style=\"width : 256px; height : 256px; padding : 0 0 0 0; margin-left : auto; margin-right : auto; border : 0;\">\n"
      "<img id=\"%s_matrix_img\" name=\"%s_matrix_img\" src=\"/i/%s.bmp?x=128&y=128\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\">\n"
      "</div>\n"
      "</div>\n",
			tag, tag, tag, tag, tag);
  shbuf_catstr(buff, html);

}

void http_matrix_content(httpreq_t *req, const char *tag)
{
	shbuf_t *buff = req->buff;
	char html[4096];
	char label[256];

	memset(label, 0, sizeof(label));
	strncpy(label, tag, sizeof(label));
	label[0] = toupper(label[0]);

	sprintf(html,
			"<div style=\"margin-top : 64px; height : 0px;\"></div>\n"
			"\n"
			"<div style=\"width : 512px; margin-left : auto; margin-right : auto;\">\n"
			"<div style=\"float : right; margin-right : 32px;\"> <span>%s Matrix</span> </div>\n"
			"<div style=\"float : left; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\">\n"
			"<span id=\"%s_matrix_lbl\">x1</span>\n"
			"</div>\n",
			label, tag);
	shbuf_catstr(buff, html);

	sprintf(html, /* expand */
      "<div style=\"float : left; margin-left : 16px; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\"><a href=\"/i/%s.bmp?span=0.1&x=128&y=128\" id=\"%s_matrix_ref\"><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+AHFRcvLtjUSsgAAAGqSURBVEhL5ZVBbtRAEEV/VTViMXcB5QZhzwoWSGEBEkJwBKJIiZBAuUOEFNYBzgA3AImDsMoiyL8+i3TPmLGNx4Edb9N2d5W/67e7DOyIpBNtOJmLb/hcwN+ySEDSXMiARQJmNhcyYJHATVgk8E8syszfxj5TFpEEMJ4zEHB3kHzgvntxEQGSD8dy1jNd1wEASD4D8GkQiVmLPpJ8DmwqAnoC7r4i+drM3k1YIWAtMlAyM5jZGck3ZrZq8wUASN6VdO7uezXZJL0CcLvGCcB+T3i/CrWJqxZnZkeZeZ/k04j4BpIHJK8yU5KytoI2bpMza9cXmSL5k+TjUqtob7L8JG2huk+12lsGACT3ALx39zuoFgE4xJZFAO7V+88AvqBnkaRTM5Mkk/QdwJOI+IpGZq5Ivs1MZeZgEyUd9+w4HllXzT3tum69yeuvSNJlRBxJeqHxz7Fv38DKzISkl+5+6O6Xbb60i4ho4xnJH9sPmEPSo1LKBXB9WBujrSIiPvQPS2OiMpBEKeViLGe0VQCbivpM9aJe9YO13RvODVkkMGXRn1gk8H/+0X4B9mM0rhW8WLcAAAAASUVORK5CYII=\" style=\"width : 15px; height : 15px;\" alt=\"Expand Image\"></a></div>\n"
      "<div style=\"clear : both;\"></div>\n"
      "<hr style=\"width : 80%;\">\n"
      "<div id=\"%s_matrix\" name=\"%s_matrix\" style=\"width : 512px; height : 512px; padding : 0 0 0 0; margin : 0 0 0 0; border : 0;\" onclick=\"matrixClick(this)\">\n"
      "<img id=\"%s_matrix_img\" name=\"%s_matrix_img\" src=\"\" style=\"width : 512px; height : 512px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\">\n"
      "</div>\n"
      "</div>\n",
			tag, tag, tag, tag, tag, tag);
  shbuf_catstr(buff, html);

	/* javascript */
	sprintf(html,
			"<script type=\"text/javascript\">\n"
			"document.getElementById(\"%s_matrix\").addEventListener(\"click\", clickPos, false);\n"
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
			"  m%sClick = true;\n"
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
			"    i = document.getElementById(\"%s_matrix_img\");\n"
			"    l = document.getElementById(\"%s_matrix_lbl\");\n"
			"  } else if (mValidateClick) {\n"
			"    i = document.getElementById(\"validate_matrix_img\");\n"
			"    l = document.getElementById(\"validate_matrix_lbl\");\n"
			"  }\n"
			"  mSpringClick = false;\n"
			"  mValidateClick = false;\n"
			"  if (i == null || l == null)\n"
			"    return;\n"
			"\n"
			"  var srcX = (clientX - offsetX) / 2;\n"
			"  var srcY = (clientY - offsetY) / 2;\n"
			"  i.src = \"/i/%s.bmp?span=0.5&y=\" + srcY + \"&x=\" + srcX + \"&zoom=\" + zoom;\n"
			"  l.innerHTML = \"x\" + (1 / zoom);\n"
			"\n"
			"  if (zoom < 0.001) {\n"
			"    zoom = 1.0;\n"
			"    clientX = offsetX + 256.0;\n"
			"    clientY = offsetY + 256.0;\n"
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
			"  clientX = 256.0;\n"
			"  clientY = 256.0;\n"
			"}\n"
			"initMatrix();\n"
			"m%sClick = true;\n"
			"printMatrix();\n"
			"</script>\n",
		tag, label, tag, tag, tag, label);
  shbuf_catstr(buff, html);

}

void http_matrix_spring_content(httpreq_t *req)
{
	http_matrix_content(req, "spring");
}

void http_matrix_spring_blurb(httpreq_t *req)
{
	http_matrix_blurb(req, "spring");
}

void http_matrix_validate_content(httpreq_t *req)
{
	http_matrix_content(req, "validate");
}

void http_matrix_validate_blurb(httpreq_t *req)
{
	http_matrix_blurb(req, "validate");
}


