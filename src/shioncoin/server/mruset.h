
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#ifndef __MRUSET_H
#define __MRUSET_H

#include <set>
#include <deque>

/** STL-like set container that only keeps the most recent N elements. */
template <typename T> class mruset
{
	public:
		typedef T key_type;
		typedef T value_type;
		typedef typename std::set<T>::iterator iterator;
		typedef typename std::set<T>::const_iterator const_iterator;
		typedef typename std::set<T>::size_type size_type;

	protected:
		std::set<T> set;
		std::deque<T> queue;
		size_type nMaxSize;

	public:
		mruset(size_type nMaxSizeIn = 0) { nMaxSize = nMaxSizeIn; }
		iterator begin() const { return set.begin(); }
		iterator end() const { return set.end(); }
		size_type size() const { return set.size(); }
		bool empty() const { return set.empty(); }
		iterator find(const key_type& k) const { return set.find(k); }
		size_type count(const key_type& k) const { return set.count(k); }
		bool inline friend operator==(const mruset<T>& a, const mruset<T>& b) { return a.set == b.set; }
		bool inline friend operator==(const mruset<T>& a, const std::set<T>& b) { return a.set == b; }
		bool inline friend operator<(const mruset<T>& a, const mruset<T>& b) { return a.set < b.set; }
		std::pair<iterator, bool> insert(const key_type& x)
		{
			std::pair<iterator, bool> ret = set.insert(x);
			if (ret.second)
			{
				if (nMaxSize && queue.size() == nMaxSize)
				{
					set.erase(queue.front());
					queue.pop_front();
				}
				queue.push_back(x);
			}
			return ret;
		}
		size_type max_size() const { return nMaxSize; }
		size_type max_size(size_type s)
		{
			if (s)
				while (queue.size() > s)
				{
					set.erase(queue.front());
					queue.pop_front();
				}
			nMaxSize = s;
			return nMaxSize;
		}
};

#endif
