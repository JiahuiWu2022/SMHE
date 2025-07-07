/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFTESTSCHEME_H_
#define MFHE_MFTESTSCHEME_H_

class MFTestScheme {
public:


	//----------------------------------------------------------------------------------
	//   STANDARD TESTS
	//----------------------------------------------------------------------------------

	static void testGadgetDecompose(long logN, long logQ, long logp, long logSlots, long num_parties);

	static void testGadgetEncryption(long logN, long logQ, long logp, long logSlots, long num_parties);

	static void testExternalProduct(long logN, long logQ, long logp, long logSlots);

	/**
	 * Testing encoding, decoding, add, and mult timing of the ciphertext
	 * c(m_1, ..., m_slots)
	 * @param[in] logN: input parameter for Params class
	 * @param[in] logQ: input parameter for Params class
	 * @param[in] logp: log of precision
	 * @param[in] logSlots: log of number of slots
	 */
	static void testSecureMFHE(long logN, long logQ, long logp, long logSlots, long num_parties);	
};

#endif
