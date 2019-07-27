
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef SERVER__UI_INTERFACE_H
#define SERVER__UI_INTERFACE_H

#include <string>
#include "util.h" // for int64
#//include <boost/signals2/signal.hpp>
//#include <boost/signals2/last_value.hpp>

class CBasicKeyStore;
class CWallet;
class uint256;

/** General change type (added, updated, removed). */
enum ChangeType
{
    CT_NEW,
    CT_UPDATED,
    CT_DELETED
};

/** Signals for UI communication. */
class CClientUIInterface
{
public:
    /** Flags for CClientUIInterface::ThreadSafeMessageBox */
    enum MessageBoxFlags
    {
        YES                   = 0x00000002,
        OK                    = 0x00000004,
        NO                    = 0x00000008,
        YES_NO                = (YES|NO),
        CANCEL                = 0x00000010,
        APPLY                 = 0x00000020,
        CLOSE                 = 0x00000040,
        OK_DEFAULT            = 0x00000000,
        YES_DEFAULT           = 0x00000000,
        NO_DEFAULT            = 0x00000080,
        CANCEL_DEFAULT        = 0x80000000,
        ICON_EXCLAMATION      = 0x00000100,
        ICON_HAND             = 0x00000200,
        ICON_WARNING          = ICON_EXCLAMATION,
        ICON_ERROR            = ICON_HAND,
        ICON_QUESTION         = 0x00000400,
        ICON_INFORMATION      = 0x00000800,
        ICON_STOP             = ICON_HAND,
        ICON_ASTERISK         = ICON_INFORMATION,
        ICON_MASK             = (0x00000100|0x00000200|0x00000400|0x00000800),
        FORWARD               = 0x00001000,
        BACKWARD              = 0x00002000,
        RESET                 = 0x00004000,
        HELP                  = 0x00008000,
        MORE                  = 0x00010000,
        SETUP                 = 0x00020000,
        // Force blocking, modal message box dialog (not just OS notification)
        MODAL                 = 0x00040000
    };
};

inline std::string _(const char* psz)
{
    return psz;
}

#endif /* ndef SERVER__UI_INTERFACE_H */

