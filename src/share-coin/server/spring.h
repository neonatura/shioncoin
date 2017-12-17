
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

#ifndef __SERVER__SPRING_H__
#define __SERVER__SPRING_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * The spring matrix contains one million pre-initialized geodetic locations in a 256x256 grid. 
 *
 * Locations are stored as two sets of bitvectors pertaining to the latitude and longitude. Each 'tude references two bits in individual bitvectors for a particular grid location.
 *
 * A location can be <i>claimed</i>, for a reward of a single coin, by relaying a 'ident stamp' transaction. This transactions contains geodetic information and the payee reward coin address. Once a location has been claimed a single latitude and longitude bit will be erased from the matrix. A miniaturized version of the matrix is sent in order to ensure the matrix's integrity between coin services.
 *
 * Unless otherwise restricted due to the interface, for example a mobile app, their is no discimination towards <i>claiming</i> any particular geo location. Identifying each location in the matrix requires four SHA1 hash operations thereby making it difficult, excluding the initial "easier" location, to scan the entire matrix in any negligible amount of time.
 *
 * @ingroup sharecoin_shc
 * @defgroup sharecoin_shcspring The spring geodetic matrix.
 * @{
 */


/**
 * The matrix grid's latitude offset adjustment.
 * @note The continental US ranges from (49°23'4.1" N) to (24°31′15″ N) latitude. */
#define SPRING_OFFSET_LATITUDE 30.0
/**
 * The matrix grid's longitude offset adjustment.
 * @note The continental US ranges from (66°57' W) to (124°46' W) longitude. 
 */  
#define SPRING_OFFSET_LONGITUDE 70.0

#define SPRING_Y_FACTOR 13.4

#define SPRING_X_FACTOR 5.2



/**
 * Set's a particular location as active inside the matrix.
 */
void spring_loc_set(double lat, double lon);

/**
 * Whether or not a particular location is set in the matrix.
 * @param lat The latitude of the geo location. 
 * @param lon The longitude of the geo location. 
 * @returns TRUE if the location matches and FALSE if not.
 * @note The latitude and longitude are not limited in range.
 */
int is_spring_loc(double lat, double lon);

/**
 * Search the surrounding area for a location registered in the matrix.
 * @param lat_p Filled with the found latitude.
 * @param lon_p Filled with the found longitude.
 * @returns SHERR_NOENT when no location is found, and "0" on success.
 */
int spring_loc_search(double cur_lat, double cur_lon, double *lat_p, double *lon_p);

/**
 * Render the spring matrix as a fractal BMP image.
 * @param zoom The degree (10.0 - 0.001) to zoom into the center.
 * @param span The ratio (1.0 is 256x256 pixels) to rende the image.
 * @param x_of A pixel offset from the left.
 * @param y_of A pixel offset from the top.
 */
int spring_render_fractal(char *img_path, double zoom, double span, double x_of, double y_of);

/**
 * Mark a particular geo location as no longer available in the spring matrix.
 * @param lat The latitude of the geo location.
 * @param lon The longitude of the geo location.
 */
void spring_loc_claim(double lat, double lon);

/**
 * Render the current form of the spring matrix in a <i>compress</i> 3x3 multi-dimensional array.
 * @param A multi-dimension (3x3) unsigned integer array.
 */
void spring_matrix_compress(uint32_t matrix[3][3]);



/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER_SPRING_H__ */




