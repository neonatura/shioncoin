
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __FRACTAL__FRACTAL_H__
#define __FRACTAL__FRACTAL_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @ingroup sharecoin
 * @defgroup sharecoin_fractal Fractal image renderer.
 * @{
 */

#include "fractal_bmp.h"

/**
 * Render a fractal BMP image given a specified seed value.
 * @param in_seed The seed value that determines the fractal's layout.
 * @param zoom The degree (10.0 - 0.001) to zoom into the center.
 * @param span The ratio (1.0 is 256x256 pixels) to rende the image.
 * @param x_of A pixel offset from the left.
 * @param y_of A pixel offset from the top.
 */
int fractal_render(char *img_path, double in_seed, double zoom, double span, double x_of, double y_of);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER_SPRING_H__ */




