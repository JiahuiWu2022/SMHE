/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/

#ifndef MFHE_MASKRESULTS_H_
#define MFHE_MASKRESULTS_H_

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <vector>
#include <stdexcept>
#include "NumUtils.h"
#include "Ring2Utils.h"
#include "Context.h"
#include "MFCiphertext.h"

using namespace std;
using namespace NTL;


struct MaskResults {
    MFCiphertext cz;
    MFCiphertext Gamma;
};

#endif