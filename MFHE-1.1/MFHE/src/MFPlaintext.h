/*
* Copyright (c) by Pengcheng Lab. and CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFPLAINTEXT_H_
#define MFHE_MFPLAINTEXT_H_

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

using namespace std;
using namespace NTL;

class MFPlaintext {
public:

	ZZX mx; ///< message mod X^N + 1

	long logp; ///< number of quantized bits
	long logq; ///< number of bits in modulus
	long slots; ///< number of slots in message

	bool isComplex; ///< option of Message with single real slot
	long party_id;
	//-----------------------------------------

	/**
	 * Plaintext: mx
	 * @param[in] mx: ZZX polynomial
	 * @param[in] logp: number of quantized bits
	 * @param[in] logq: number of bits in modulus
	 * @param[in] slots: number of slots in message
	 * @param[in] isComplex: option of Message with single real slot
	 */
	MFPlaintext(ZZX mx = ZZX::zero(), long logp = 0, long logq = 0, long slots = 1, bool isComplex = true, long party_id = 0) : mx(mx), logp(logp), logq(logq), slots(slots), isComplex(isComplex), party_id(party_id) {}

	/**
	 * Copy Constructor
	 */
	MFPlaintext(const MFPlaintext& o) : mx(o.mx), logp(o.logp), logq(o.logq), slots(o.slots), isComplex(o.isComplex), party_id(o.party_id) {}
};

#endif
