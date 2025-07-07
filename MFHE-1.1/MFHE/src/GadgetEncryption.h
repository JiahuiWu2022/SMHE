/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/

#ifndef MFHE_GECIPHERTEXT_H_
#define MFHE_GECIPHERTEXT_H_

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <vector>
#include <stdexcept>
#include "NumUtils.h"
#include "Ring2Utils.h"
#include "Context.h"
#include "MFPlaintext.h"

using namespace std;
using namespace NTL;


struct GadgetEncryption {
    vector<ZZX> u0;
    vector<ZZX> u1;
};

#endif