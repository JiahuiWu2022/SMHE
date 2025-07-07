/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/

#include "../src/MFHE.h"

using namespace std;
using namespace NTL;

int main() {
	
	/* Test <h(a),g> =? a (mod Q) 
	 * Params: logN>8, logQ, logp, logSlots, num_parties
	 * Suggested: 13, 65, 30, 3, 2; (logSlots < logN)
	 */
	MFTestScheme::testGadgetDecompose(13, 65, 30, 0, 2);

	/* Test gadget encryption and decryption
	 * Params: logN>8, logQ, logp, logSlots, num_parties
	 * Suggested: 13, 65, 30, 3, 2; (logSlots < logN)
	 */
	MFTestScheme::testGadgetEncryption(13, 65, 30, 0, 2);

	/*
	 * Params: logN, logQ, logp, logSlots
	 * Suggested: 13, 65, 30, 3
	 */
	MFTestScheme::testExternalProduct(13, 65, 30, 0);

	/*
	 * Params: logN>8, logQ, logp, logSlots, num_parties
	 * Suggested: 13, 65, 30, 3, 2; (logSlots < logN)
	 */
	MFTestScheme::testSecureMFHE(14, 256, 60, 13, 2); 

	return 0;
}
