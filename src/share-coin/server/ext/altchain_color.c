/* Copyright 2018 Neo Natura */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

typedef struct rgb_t {
	uint32_t r;
	uint32_t g;
	uint32_t b;
	const char *label;
} rgb_t;

#define RGB_TABLE_MAX 464
static rgb_t _rgb_table[RGB_TABLE_MAX] =
{
	{ 255, 250, 250, "snow" },
	{ 248, 248, 255, "ghost white" },
	{ 245, 245, 245, "white smoke" },
	{ 220, 220, 220, "gainsboro" },
	{ 255, 250, 240, "floral white" },
	{ 253, 245, 230, "old lace" },
	{ 250, 240, 230, "linen" },
	{ 250, 235, 215, "antique white" },
	{ 255, 239, 213, "papaya whip" },
	{ 255, 235, 205, "blanched almond" },
	{ 255, 228, 196, "bisque" },
	{ 255, 218, 185, "peach puff" },
	{ 255, 222, 173, "navajo white" },
	{ 255, 228, 181, "moccasin" },
	{ 255, 248, 220, "cornsilk" },
	{ 255, 255, 240, "ivory" },
	{ 255, 250, 205, "lemon chiffon" },
	{ 255, 245, 238, "seashell" },
	{ 240, 255, 240, "honeydew" },
	{ 245, 255, 250, "mint cream" },
	{ 240, 255, 255, "azure" },
	{ 240, 248, 255, "alice blue" },
	{ 230, 230, 250, "lavender" },
	{ 255, 240, 245, "lavender blush" },
	{ 255, 228, 225, "mistyrose" },
	{ 255, 255, 255, "white" },
	{ 0, 0, 0, "black" },
	{ 47, 79, 79, "dark slate grey" },
	{ 105, 105, 105, "dim grey" },
	{ 112, 128, 144, "slate grey" },
	{ 119, 136, 153, "light slate grey" },
	{ 190, 190, 190, "grey" },
	{ 128, 128, 128, "grey" },
	{ 211, 211, 211, "light grey" },
	{ 25, 25, 112, "midnight blue" },
	{ 0, 0, 128, "navy" },
	{ 0, 0, 128, "navy blue" },
	{ 100, 149, 237, "cornflower blue" },
	{ 72, 61, 139, "dark slate blue" },
	{ 106, 90, 205, "slate blue" },
	{ 123, 104, 238, "medium slate blue" },
	{ 132, 112, 255, "light slate blue" },
	{ 0, 0, 205, "medium blue" },
	{ 65, 105, 225, "royal blue" },
	{ 0, 0, 255, "blue" },
	{ 30, 144, 255, "dodger blue" },
	{ 0, 191, 255, "deep sky blue" },
	{ 135, 206, 235, "sky blue" },
	{ 135, 206, 250, "light sky blue" },
	{ 70, 130, 180, "steel blue" },
	{ 176, 196, 222, "light steel blue" },
	{ 173, 216, 230, "light blue" },
	{ 176, 224, 230, "powder blue" },
	{ 175, 238, 238, "pale turquoise" },
	{ 0, 206, 209, "dark turquoise" },
	{ 72, 209, 204, "medium turquoise" },
	{ 64, 224, 208, "turquoise" },
	{ 0, 255, 255, "cyan" },
	{ 0, 255, 255, "aqua" },
	{ 224, 255, 255, "light cyan" },
	{ 95, 158, 160, "cadet blue" },
	{ 102, 205, 170, "medium aqua marine" },
	{ 127, 255, 212, "aqua marine" },
	{ 0, 100, 0, "dark green" },
	{ 85, 107, 47, "dark olive green" },
	{ 143, 188, 143, "dark sea green" },
	{ 46, 139, 87, "seagreen" },
	{ 60, 179, 113, "mediumseagreen" },
	{ 32, 178, 170, "lightseagreen" },
	{ 152, 251, 152, "palegreen" },
	{ 0, 255, 127, "springgreen" },
	{ 124, 252, 0, "lawngreen" },
	{ 0, 255, 0, "green" },
	{ 0, 255, 0, "lime" },
	{ 0, 255, 0, "green" },
	{ 0, 128, 0, "green" },
	{ 127, 255, 0, "chartreuse" },
	{ 0, 250, 154, "mediumspringgreen" },
	{ 173, 255, 47, "greenyellow" },
	{ 50, 205, 50, "limegreen" },
	{ 154, 205, 50, "yellowgreen" },
	{ 34, 139, 34, "forestgreen" },
	{ 107, 142, 35, "olivedrab" },
	{ 189, 183, 107, "darkkhaki" },
	{ 240, 230, 140, "khaki" },
	{ 238, 232, 170, "palegoldenrod" },
	{ 250, 250, 210, "lightgoldenrodyellow" },
	{ 255, 255, 224, "lightyellow" },
	{ 255, 255, 0, "yellow" },
	{ 255, 215, 0, "gold" },
	{ 238, 221, 130, "lightgoldenrod" },
	{ 218, 165, 32, "goldenrod" },
	{ 184, 134, 11, "darkgoldenrod" },
	{ 188, 143, 143, "rosybrown" },
	{ 205, 92, 92, "indianred" },
	{ 139, 69, 19, "saddlebrown" },
	{ 160, 82, 45, "sienna" },
	{ 205, 133, 63, "peru" },
	{ 222, 184, 135, "burlywood" },
	{ 245, 245, 220, "beige" },
	{ 245, 222, 179, "wheat" },
	{ 244, 164, 96, "sandybrown" },
	{ 210, 180, 140, "tan" },
	{ 210, 105, 30, "chocolate" },
	{ 178, 34, 34, "firebrick" },
	{ 165, 42, 42, "brown" },
	{ 233, 150, 122, "darksalmon" },
	{ 250, 128, 114, "salmon" },
	{ 255, 160, 122, "lightsalmon" },
	{ 255, 165, 0, "orange" },
	{ 255, 140, 0, "darkorange" },
	{ 255, 127, 80, "coral" },
	{ 240, 128, 128, "lightcoral" },
	{ 255, 99, 71, "tomato" },
	{ 255, 69, 0, "orangered" },
	{ 255, 0, 0, "red" },
	{ 255, 105, 180, "hotpink" },
	{ 255, 20, 147, "deeppink" },
	{ 255, 192, 203, "pink" },
	{ 255, 182, 193, "lightpink" },
	{ 219, 112, 147, "palevioletred" },
	{ 176, 48, 96, "maroon" },
	{ 176, 48, 96, "maroon" },
	{ 128, 0, 0, "maroon" },
	{ 199, 21, 133, "mediumvioletred" },
	{ 208, 32, 144, "violetred" },
	{ 255, 0, 255, "magenta" },
	{ 255, 0, 255, "fuchsia" },
	{ 238, 130, 238, "violet" },
	{ 221, 160, 221, "plum" },
	{ 218, 112, 214, "orchid" },
	{ 186, 85, 211, "mediumorchid" },
	{ 153, 50, 204, "darkorchid" },
	{ 148, 0, 211, "darkviolet" },
	{ 138, 43, 226, "blueviolet" },
	{ 160, 32, 240, "purple" },
	{ 160, 32, 240, "purple" },
	{ 128, 0, 128, "purple" },
	{ 147, 112, 219, "mediumpurple" },
	{ 216, 191, 216, "thistle" },
	{ 255, 250, 250, "snow" },
	{ 238, 233, 233, "snow" },
	{ 205, 201, 201, "snow" },
	{ 139, 137, 137, "snow" },
	{ 255, 245, 238, "seashell" },
	{ 238, 229, 222, "seashell" },
	{ 205, 197, 191, "seashell" },
	{ 139, 134, 130, "seashell" },
	{ 255, 239, 219, "antiquewhite" },
	{ 238, 223, 204, "antiquewhite" },
	{ 205, 192, 176, "antiquewhite" },
	{ 139, 131, 120, "antiquewhite" },
	{ 255, 228, 196, "bisque" },
	{ 238, 213, 183, "bisque" },
	{ 205, 183, 158, "bisque" },
	{ 139, 125, 107, "bisque" },
	{ 255, 218, 185, "peachpuff" },
	{ 238, 203, 173, "peachpuff" },
	{ 205, 175, 149, "peachpuff" },
	{ 139, 119, 101, "peachpuff" },
	{ 255, 222, 173, "navajo white" },
	{ 238, 207, 161, "navajo white" },
	{ 205, 179, 139, "navajo white" },
	{ 139, 121, 94, "navajo white" },
	{ 255, 250, 205, "lemon chiffon" },
	{ 238, 233, 191, "lemon chiffon" },
	{ 205, 201, 165, "lemon chiffon" },
	{ 139, 137, 112, "lemon chiffon" },
	{ 255, 248, 220, "cornsilk" },
	{ 238, 232, 205, "cornsilk" },
	{ 205, 200, 177, "cornsilk" },
	{ 139, 136, 120, "cornsilk" },
	{ 255, 255, 240, "ivory" },
	{ 238, 238, 224, "ivory" },
	{ 205, 205, 193, "ivory" },
	{ 139, 139, 131, "ivory" },
	{ 240, 255, 240, "honeydew" },
	{ 224, 238, 224, "honeydew" },
	{ 193, 205, 193, "honeydew" },
	{ 131, 139, 131, "honeydew" },
	{ 255, 240, 245, "lavender blush" },
	{ 238, 224, 229, "lavender blush" },
	{ 205, 193, 197, "lavender blush" },
	{ 139, 131, 134, "lavender blush" },
	{ 255, 228, 225, "misty rose" },
	{ 238, 213, 210, "misty rose" },
	{ 205, 183, 181, "misty rose" },
	{ 139, 125, 123, "misty rose" },
	{ 240, 255, 255, "azure" },
	{ 224, 238, 238, "azure" },
	{ 193, 205, 205, "azure" },
	{ 131, 139, 139, "azure" },
	{ 131, 111, 255, "slate blue" },
	{ 122, 103, 238, "slate blue" },
	{ 105, 89, 205, "slate blue" },
	{ 71, 60, 139, "slate blue" },
	{ 72, 118, 255, "royal blue" },
	{ 67, 110, 238, "royal blue" },
	{ 58, 95, 205, "royal blue" },
	{ 39, 64, 139, "royal blue" },
	{ 0, 0, 255, "blue" },
	{ 0, 0, 238, "blue" },
	{ 0, 0, 205, "blue" },
	{ 0, 0, 139, "blue" },
	{ 30, 144, 255, "dodger blue" },
	{ 28, 134, 238, "dodger blue" },
	{ 24, 116, 205, "dodger blue" },
	{ 16, 78, 139, "dodger blue" },
	{ 99, 184, 255, "steel blue" },
	{ 92, 172, 238, "steel blue" },
	{ 79, 148, 205, "steel blue" },
	{ 54, 100, 139, "steel blue" },
	{ 0, 191, 255, "deep sky blue" },
	{ 0, 178, 238, "deep sky blue" },
	{ 0, 154, 205, "deep sky blue" },
	{ 0, 104, 139, "deep sky blue" },
	{ 135, 206, 255, "sky blue" },
	{ 126, 192, 238, "sky blue" },
	{ 108, 166, 205, "sky blue" },
	{ 74, 112, 139, "sky blue" },
	{ 176, 226, 255, "light sky blue" },
	{ 164, 211, 238, "light sky blue" },
	{ 141, 182, 205, "light sky blue" },
	{ 96, 123, 139, "light sky blue" },
	{ 198, 226, 255, "slate gray" },
	{ 185, 211, 238, "slate gray" },
	{ 159, 182, 205, "slate gray" },
	{ 108, 123, 139, "slate gray" },
	{ 202, 225, 255, "lightsteelblue" },
	{ 188, 210, 238, "lightsteelblue" },
	{ 162, 181, 205, "lightsteelblue" },
	{ 110, 123, 139, "lightsteelblue" },
	{ 191, 239, 255, "lightblue" },
	{ 178, 223, 238, "lightblue" },
	{ 154, 192, 205, "lightblue" },
	{ 104, 131, 139, "lightblue" },
	{ 224, 255, 255, "lightcyan" },
	{ 209, 238, 238, "lightcyan" },
	{ 180, 205, 205, "lightcyan" },
	{ 122, 139, 139, "lightcyan" },
	{ 187, 255, 255, "paleturquoise" },
	{ 174, 238, 238, "paleturquoise" },
	{ 150, 205, 205, "paleturquoise" },
	{ 102, 139, 139, "paleturquoise" },
	{ 152, 245, 255, "cadetblue" },
	{ 142, 229, 238, "cadetblue" },
	{ 122, 197, 205, "cadetblue" },
	{ 83, 134, 139, "cadetblue" },
	{ 0, 245, 255, "turquoise" },
	{ 0, 229, 238, "turquoise" },
	{ 0, 197, 205, "turquoise" },
	{ 0, 134, 139, "turquoise" },
	{ 0, 255, 255, "cyan" },
	{ 0, 238, 238, "cyan" },
	{ 0, 205, 205, "cyan" },
	{ 0, 139, 139, "cyan" },
	{ 151, 255, 255, "darkslategray" },
	{ 141, 238, 238, "darkslategray" },
	{ 121, 205, 205, "darkslategray" },
	{ 82, 139, 139, "darkslategray" },
	{ 127, 255, 212, "aquamarine" },
	{ 118, 238, 198, "aquamarine" },
	{ 102, 205, 170, "aquamarine" },
	{ 69, 139, 116, "aquamarine" },
	{ 193, 255, 193, "darkseagreen" },
	{ 180, 238, 180, "darkseagreen" },
	{ 155, 205, 155, "darkseagreen" },
	{ 105, 139, 105, "darkseagreen" },
	{ 84, 255, 159, "seagreen" },
	{ 78, 238, 148, "seagreen" },
	{ 67, 205, 128, "seagreen" },
	{ 46, 139, 87, "seagreen" },
	{ 154, 255, 154, "palegreen" },
	{ 144, 238, 144, "palegreen" },
	{ 124, 205, 124, "palegreen" },
	{ 84, 139, 84, "palegreen" },
	{ 0, 255, 127, "springgreen" },
	{ 0, 238, 118, "springgreen" },
	{ 0, 205, 102, "springgreen" },
	{ 0, 139, 69, "springgreen" },
	{ 0, 255, 0, "green" },
	{ 0, 238, 0, "green" },
	{ 0, 205, 0, "green" },
	{ 0, 139, 0, "green" },
	{ 127, 255, 0, "chartreuse" },
	{ 118, 238, 0, "chartreuse" },
	{ 102, 205, 0, "chartreuse" },
	{ 69, 139, 0, "chartreuse" },
	{ 192, 255, 62, "olivedrab" },
	{ 179, 238, 58, "olivedrab" },
	{ 154, 205, 50, "olivedrab" },
	{ 105, 139, 34, "olivedrab" },
	{ 202, 255, 112, "darkolivegreen" },
	{ 188, 238, 104, "darkolivegreen" },
	{ 162, 205, 90, "darkolivegreen" },
	{ 110, 139, 61, "darkolivegreen" },
	{ 255, 246, 143, "khaki" },
	{ 238, 230, 133, "khaki" },
	{ 205, 198, 115, "khaki" },
	{ 139, 134, 78, "khaki" },
	{ 255, 236, 139, "lightgoldenrod" },
	{ 238, 220, 130, "lightgoldenrod" },
	{ 205, 190, 112, "lightgoldenrod" },
	{ 139, 129, 76, "lightgoldenrod" },
	{ 255, 255, 224, "lightyellow" },
	{ 238, 238, 209, "lightyellow" },
	{ 205, 205, 180, "lightyellow" },
	{ 139, 139, 122, "lightyellow" },
	{ 255, 255, 0, "yellow" },
	{ 238, 238, 0, "yellow" },
	{ 205, 205, 0, "yellow" },
	{ 139, 139, 0, "yellow" },
	{ 255, 215, 0, "gold" },
	{ 238, 201, 0, "gold" },
	{ 205, 173, 0, "gold" },
	{ 139, 117, 0, "gold" },
	{ 255, 193, 37, "goldenrod" },
	{ 238, 180, 34, "goldenrod" },
	{ 205, 155, 29, "goldenrod" },
	{ 139, 105, 20, "goldenrod" },
	{ 255, 185, 15, "darkgoldenrod" },
	{ 238, 173, 14, "darkgoldenrod" },
	{ 205, 149, 12, "darkgoldenrod" },
	{ 139, 101, 8, "darkgoldenrod" },
	{ 255, 193, 193, "rosybrown" },
	{ 238, 180, 180, "rosybrown" },
	{ 205, 155, 155, "rosybrown" },
	{ 139, 105, 105, "rosybrown" },
	{ 255, 106, 106, "indianred" },
	{ 238, 99, 99, "indianred" },
	{ 205, 85, 85, "indianred" },
	{ 139, 58, 58, "indianred" },
	{ 255, 130, 71, "sienna" },
	{ 238, 121, 66, "sienna" },
	{ 205, 104, 57, "sienna" },
	{ 139, 71, 38, "sienna" },
	{ 255, 211, 155, "burlywood" },
	{ 238, 197, 145, "burlywood" },
	{ 205, 170, 125, "burlywood" },
	{ 139, 115, 85, "burlywood" },
	{ 255, 231, 186, "wheat" },
	{ 238, 216, 174, "wheat" },
	{ 205, 186, 150, "wheat" },
	{ 139, 126, 102, "wheat" },
	{ 255, 165, 79, "tan" },
	{ 238, 154, 73, "tan" },
	{ 205, 133, 63, "tan" },
	{ 139, 90, 43, "tan" },
	{ 255, 127, 36, "chocolate" },
	{ 238, 118, 33, "chocolate" },
	{ 205, 102, 29, "chocolate" },
	{ 139, 69, 19, "chocolate" },
	{ 255, 48, 48, "firebrick" },
	{ 238, 44, 44, "firebrick" },
	{ 205, 38, 38, "firebrick" },
	{ 139, 26, 26, "firebrick" },
	{ 255, 64, 64, "brown" },
	{ 238, 59, 59, "brown" },
	{ 205, 51, 51, "brown" },
	{ 139, 35, 35, "brown" },
	{ 255, 140, 105, "salmon" },
	{ 238, 130, 98, "salmon" },
	{ 205, 112, 84, "salmon" },
	{ 139, 76, 57, "salmon" },
	{ 255, 160, 122, "lightsalmon" },
	{ 238, 149, 114, "lightsalmon" },
	{ 205, 129, 98, "lightsalmon" },
	{ 139, 87, 66, "lightsalmon" },
	{ 255, 165, 0, "orange" },
	{ 238, 154, 0, "orange" },
	{ 205, 133, 0, "orange" },
	{ 139, 90, 0, "orange" },
	{ 255, 127, 0, "darkorange" },
	{ 238, 118, 0, "darkorange" },
	{ 205, 102, 0, "darkorange" },
	{ 139, 69, 0, "darkorange" },
	{ 255, 114, 86, "coral" },
	{ 238, 106, 80, "coral" },
	{ 205, 91, 69, "coral" },
	{ 139, 62, 47, "coral" },
	{ 255, 99, 71, "tomato" },
	{ 238, 92, 66, "tomato" },
	{ 205, 79, 57, "tomato" },
	{ 139, 54, 38, "tomato" },
	{ 255, 69, 0, "orangered" },
	{ 238, 64, 0, "orangered" },
	{ 205, 55, 0, "orangered" },
	{ 139, 37, 0, "orangered" },
	{ 255, 0, 0, "red" },
	{ 238, 0, 0, "red" },
	{ 205, 0, 0, "red" },
	{ 139, 0, 0, "red" },
	{ 255, 20, 147, "deeppink" },
	{ 238, 18, 137, "deeppink" },
	{ 205, 16, 118, "deeppink" },
	{ 139, 10, 80, "deeppink" },
	{ 255, 110, 180, "hotpink" },
	{ 238, 106, 167, "hotpink" },
	{ 205, 96, 144, "hotpink" },
	{ 139, 58, 98, "hotpink" },
	{ 255, 181, 197, "pink" },
	{ 238, 169, 184, "pink" },
	{ 205, 145, 158, "pink" },
	{ 139, 99, 108, "pink" },
	{ 255, 174, 185, "lightpink" },
	{ 238, 162, 173, "lightpink" },
	{ 205, 140, 149, "lightpink" },
	{ 139, 95, 101, "lightpink" },
	{ 255, 130, 171, "palevioletred" },
	{ 238, 121, 159, "palevioletred" },
	{ 205, 104, 137, "palevioletred" },
	{ 139, 71, 93, "palevioletred" },
	{ 255, 52, 179, "maroon" },
	{ 238, 48, 167, "maroon" },
	{ 205, 41, 144, "maroon" },
	{ 139, 28, 98, "maroon" },
	{ 255, 62, 150, "violetred" },
	{ 238, 58, 140, "violetred" },
	{ 205, 50, 120, "violetred" },
	{ 139, 34, 82, "violetred" },
	{ 255, 0, 255, "magenta" },
	{ 238, 0, 238, "magenta" },
	{ 205, 0, 205, "magenta" },
	{ 139, 0, 139, "magenta" },
	{ 255, 131, 250, "orchid" },
	{ 238, 122, 233, "orchid" },
	{ 205, 105, 201, "orchid" },
	{ 139, 71, 137, "orchid" },
	{ 255, 187, 255, "plum" },
	{ 238, 174, 238, "plum" },
	{ 205, 150, 205, "plum" },
	{ 139, 102, 139, "plum" },
	{ 224, 102, 255, "mediumorchid" },
	{ 209, 95, 238, "mediumorchid" },
	{ 180, 82, 205, "mediumorchid" },
	{ 122, 55, 139, "mediumorchid" },
	{ 191, 62, 255, "darkorchid" },
	{ 178, 58, 238, "darkorchid" },
	{ 154, 50, 205, "darkorchid" },
	{ 104, 34, 139, "darkorchid" },
	{ 155, 48, 255, "purple" },
	{ 145, 44, 238, "purple" },
	{ 125, 38, 205, "purple" },
	{ 85, 26, 139, "purple" },
	{ 171, 130, 255, "mediumpurple" },
	{ 159, 121, 238, "mediumpurple" },
	{ 137, 104, 205, "mediumpurple" },
	{ 93, 71, 139, "mediumpurple" },
	{ 255, 225, 255, "thistle" },
	{ 238, 210, 238, "thistle" },
	{ 205, 181, 205, "thistle" },
	{ 139, 123, 139, "thistle" },
	{ 169, 169, 169, "darkgrey" },
	{ 0, 0, 139, "darkblue" },
	{ 0, 139, 139, "darkcyan" },
	{ 139, 0, 139, "darkmagenta" },
	{ 139, 0, 0, "darkred" },
	{ 144, 238, 144, "lightgreen" },
	{ 220, 20, 60, "crimson" },
	{ 75, 0, 130, "indigo" },
	{ 128, 128, 0, "olive" },
	{ 102, 51, 153, "rebeccapurple" },
	{ 192, 192, 192, "silver" },
	{ 0, 128, 128, "teal" }
};

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))
static int levenshtein(const char *s1, const char *s2) 
{
	unsigned int x, y, s1len, s2len;
	s1len = strlen(s1);
	s2len = strlen(s2);
	unsigned int matrix[s2len+1][s1len+1];
	matrix[0][0] = 0;
	for (x = 1; x <= s2len; x++)
		matrix[x][0] = matrix[x-1][0] + 1;
	for (y = 1; y <= s1len; y++)
		matrix[0][y] = matrix[0][y-1] + 1;
	for (x = 1; x <= s2len; x++)
		for (y = 1; y <= s1len; y++)
			matrix[x][y] = MIN3(matrix[x-1][y] + 1, matrix[x][y-1] + 1, matrix[x-1][y-1] + (s1[y-1] == s2[x-1] ? 0 : 1));

	return(matrix[s2len][s1len]);
}

static int _str_span(const char *str1, const char *str2)
{
	return (int)((double)(strlen(str1) * strlen(str2)) /
			(double)levenshtein(str1, str2));
}

static const char *_str_ucword(const char *str)
{
	static char ret_buf[1024];
	int i;

	memset(ret_buf, '\000', sizeof(ret_buf));
	for (i = 0; i < strlen(str) && i < sizeof(ret_buf); i++) {
		if (i == 0 || !isalpha(str[i-1]))
			ret_buf[i] = toupper(str[i]);
		else
			ret_buf[i] = tolower(str[i]);
	}

	return ((const char *)ret_buf);
}

static const char *_str_abrev(const char *str)
{
	static char ret_buf[1024];
	int i, j;

	memset(ret_buf, '\000', sizeof(ret_buf));
	j = -1;
	for (i = 0; i < strlen(str) && i < sizeof(ret_buf); i++) {
		if (!isalpha(str[i]))
			continue;
		if (i == 0 || !isalpha(str[i-1]))
			ret_buf[++j] = toupper(str[i]);
	}

	return ((const char *)ret_buf);
}

void color_gen(char *name, uint32_t *red_p, uint32_t *green_p, uint32_t *blue_p, uint32_t *alpha_p, char *ret_label, char *ret_abrev)
{
	rgb_t *pri_color;
	rgb_t *sec_color;
	rgb_t *tri_color;
	char name_buf[128];
	uint64_t r, g, b;
	int score[RGB_TABLE_MAX];
	int pri_score, sec_score, tri_score;
	int i;

	*red_p = *green_p = *blue_p = *alpha_p = ~0;

	memset(name_buf, 0, sizeof(name_buf));
	for (i = 0; i < strlen(name) && i < 127; i++) {
		name_buf[i] = tolower(name[i]);
	}

	for (i = 0; i < RGB_TABLE_MAX; i++) {
		score[i] = _str_span(name_buf, _rgb_table[i].label);
	}

	pri_score = 0;
	pri_color = NULL;
	for (i = 0; i < RGB_TABLE_MAX; i++) {
		if (score[i] > pri_score) {
			pri_color = &_rgb_table[i];
			pri_score = score[i];
		}
	}

	sec_score = 0;
	sec_color = NULL;
	for (i = 0; i < RGB_TABLE_MAX; i++) {
		if (_rgb_table[i].label == pri_color->label)
			continue;

		if (score[i] > sec_score) {
			sec_color = &_rgb_table[i];
			sec_score = score[i];
		}
	}

	tri_score = 0;
	tri_color = NULL;
	for (i = 0; i < RGB_TABLE_MAX; i++) {
		if (_rgb_table[i].label == pri_color->label ||
				_rgb_table[i].label == sec_color->label)
			continue;

		if (score[i] > tri_score) {
			tri_color = &_rgb_table[i];
			tri_score = score[i];
		}
	}

//	printf ("PRI: {%d,%d,%d} = \"%s\"\n", pri_color->r, pri_color->g, pri_color->b, pri_color->label);
//	printf ("SEC: {%d,%d,%d} = \"%s\"\n", sec_color->r, sec_color->g, sec_color->b, sec_color->label);
//	printf ("TRI: {%d,%d,%d} = \"%s\"\n", tri_color->r, tri_color->g, tri_color->b, tri_color->label);

	*alpha_p = ~0;

	r = (uint64_t)(pri_color->r << 24) * 4 + 
		(uint64_t)(sec_color->r << 24) * 3 + 
		(uint64_t)(tri_color->r << 24);
	*alpha_p -= (uint32_t)(r >> 8);
	r /= 8;
	r += (tri_color->r % 65536);
	*red_p = (uint32_t)r;

	g = (uint64_t)(pri_color->g << 24) * 4 + 
		(uint64_t)(sec_color->g << 24) * 3 + 
		(uint64_t)(tri_color->g << 24);
	*alpha_p -= (uint32_t)(g >> 8);
	g /= 8;
	g += (tri_color->g % 65536);
	*green_p = (uint32_t)g;

	b = (uint64_t)(pri_color->b << 24) * 4 + 
		(uint64_t)(sec_color->b << 24) * 3 + 
		(uint64_t)(tri_color->b << 24);
	*alpha_p -= (uint32_t)(b >> 8);
	b /= 8;
	b += (tri_color->b % 65536);
	*blue_p = (uint32_t)b;

	strcpy(ret_label, _str_ucword(pri_color->label));
	strcat(ret_label, " ");
	strcat(ret_label, _str_ucword(sec_color->label));
	strcat(ret_label, " (");
	strcat(ret_label, _str_abrev(tri_color->label));
	strcat(ret_label, ")");

	memset(ret_abrev, '\000', 5);
	strncpy(ret_abrev, _str_abrev(ret_label), 4);
	if (strlen(ret_abrev) < 4) {
		int sum = 0;
		for (i = 0; i < strlen(ret_label); i++) {
			sum += (int)tolower(ret_label[i]);
		}
		sprintf(ret_abrev + strlen(ret_abrev), "%d", (sum % 10));
	}
}

