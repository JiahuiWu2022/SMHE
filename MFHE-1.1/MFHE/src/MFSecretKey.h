/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFSECRETKEY_H_
#define MFHE_MFSECRETKEY_H_

#include <NTL/ZZX.h>

#include "NumUtils.h"

using namespace std;
using namespace NTL;


class MFSecretKey:public NumUtils {
public:

	ZZX sx; ///< secret key

	MFSecretKey(long logN, long h = 64);

	MFSecretKey(ZZX sx = ZZX::zero()) : sx(sx) {};
	MFSecretKey(const MFSecretKey& o) : sx(o.sx) {};

};

#endif