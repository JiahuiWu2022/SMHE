/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFSERIALIZATIONUTILS_H_
#define MFHE_MFSERIALIZATIONUTILS_H_

#include <iostream>

#include "MFCiphertext.h"
#include "MFPlaintext.h"
#include "MFScheme.h"
#include "MFSecretKey.h"
#include "Context.h"

using namespace std;
using namespace NTL;

class MFSerializationUtils {
public:

	static void writeCiphertext(MFCiphertext& ciphertext, string path);
	static MFCiphertext readCiphertext(string path);

	static void writePlaintext(MFPlaintext& plaintext, string path);
	static MFPlaintext readPlaintext(string path);

	static void writeContext(Context& context, string path);
	static Context readContext(string path);

	static void writeSchemeKeys(MFScheme& scheme, string path);
	static void readSchemeKeys(MFScheme& scheme, string path);

	static void writeSecretKey(MFSecretKey& secretKey, string path);
	static MFSecretKey readSecretKey(string path);

	static void writeKey(MFKey& key, string path);
	static MFKey readKey(string path);
};

#endif /* SERIALIZATIONUTILS_H_ */
