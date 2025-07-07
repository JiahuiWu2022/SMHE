/*
* Copyright (c) by Pengcheng Lab and CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFSCHEME_H_
#define MFHE_MFSCHEME_H_

#include "Common.h"
#include "MFCiphertext.h"
#include "GadgetEncryption.h"
#include "MaskResults.h"
#include "Context.h"
#include "MFKey.h"
#include "MFPlaintext.h"
#include "MFSecretKey.h"

#include <complex>

using namespace std;
using namespace NTL;

static long ENCRYPTION = 0;
static long MULTIPLICATION  = 0;
static long CONJUGATION = 6;


class MFScheme {
private:
public:
	Context& context;

	map<long, MFKey> mfKeyMap; ///< contain multiple Encryption and Decryption keys for MFHE
	map<long, MFKey> leftRotKeyMap; ///< contain left rotation keys, if generated

	MFScheme(Context& context);

	MFScheme(MFSecretKey& mfSecretKey, Context& context);

	MFScheme(MFSecretKey& mfSecretKey, ZZX& ax, Context& context);


	//----------------------------------------------------------------------------------
	//   KEYS GENERATION
	//----------------------------------------------------------------------------------

	/**
	 * generates key for MFHE (key is stored in mfKeyMap)
	 */
	void addMFEncKey(MFSecretKey& mfSecretKey);
	void addMFEncKey(MFSecretKey& mfSecretKey, ZZX ax);

	/**
	 * generates key for conjugation (key is stored in keyMap)
	 */
	void addConjKey(MFSecretKey& secretKey);

	/**
	 * generates key for multiplication (key is stored in keyMap)
	 */
	void addMFMultKey(MFSecretKey& mfSecretKey);

	/**
	 * generates key for left rotation (key is stored in leftRotKeyMap)
	 */
	void addLeftRotKey(MFSecretKey& secretKey, long rot);

	/**
	 * generates all keys for power-of-two left rotations (keys are stored in leftRotKeyMap)
	 */
	void addLeftRotKeys(MFSecretKey& secretKey);

	/**
	 * generates all keys for power-of-two right rotations (keys are stored in leftRotKeyMap)
	 */
	void addRightRotKeys(MFSecretKey& secretKey);

	/**
	 * generates keys for sorting (keys are stored in leftRotKeyMap)
	 */
	void addSortKeys(MFSecretKey& secretKey, long size);


	//----------------------------------------------------------------------------------
	//   ENCODING & DECODING
	//----------------------------------------------------------------------------------

	/**
	 * encodes an array of double values into a ZZX polynomial using special fft inverse
	 * @param[in] vals: array double of values
	 * @param[in] slots: size of an array
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return message
	 */
	MFPlaintext encode(double* vals, long slots, long logp, long logq);

	/**
	 * encodes an array of complex values into a ZZX polynomial using special fft inverse
	 * @param[in] vals: array complex of values
	 * @param[in] slots: size of an array
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return message
	 */
	MFPlaintext encode(complex<double>* vals, long slots, long logp, long logq);

	/**
	 * decodes a ZZX polynomial into an array of complex values using special fft
	 * @param[in] msg: message
	 * @return decoded array of complex values
	 */
	complex<double>* decode(MFPlaintext& msg);

	/**
	 * encodes a single double value into a ZZX polynomial using special fft inverse
	 * @param[in] val: double value
	 * @param[in] logp: log of message quantize bits
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return message
	 */
	MFPlaintext encodeSingle(double val, long logp, long logq);

	/**
	 * encodes a single complex value into a ZZX polynomial using special fft inverse
	 * @param[in] val: complex value
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return message
	 */
	MFPlaintext encodeSingle(complex<double> val, long logp, long logq);

	/**
	 * decodes a ZZX polynomial into a single complex value using special fft
	 * @param[in] msg: message
	 * @return decoded complex value
	 */
	complex<double> decodeSingle(MFPlaintext& msg);


	//----------------------------------------------------------------------------------
	//   ENCRYPTION & DECRYPTION
	//----------------------------------------------------------------------------------


	/**
	 * encrypts message into MFCiphertext using public key encyption
	 * @param[in] msg: message
	 * @return MFCiphertext
	 */
	MFCiphertext encryptMsg(MFPlaintext& msg);

	/**
	 * encrypts message into MFCiphertext using public key encyption
	 * @param[in] msg: message
	 * @return MFCiphertext
	 */
	MFCiphertext maskEncryptMsg(MFPlaintext& msg, ZZX& vx);		

	/**
	 * gadget encrypts message into MFCiphertext
	 * @param[in] msg: message
	 * @return MFCiphertext
	 */
	MFCiphertext gadgetEncryptMsg(MFPlaintext& msg, MFSecretKey& mfSecretKey, ZZX& logg, Context& context);	

	/**
	 * @brief verify whether gadget encryption ciphertext Gamma is correct
	 * 
	 * @param msg: message
	 * @param Gamma: gadget encryption result MFCiphertext
	 * @param mfSecretKey 
	 * @param logg: gadget vector of logarithmic elements 
	 * @param context 
	 */
	void verifyGadgetEncryption(MFPlaintext& msg, MFCiphertext& Gamma, MFSecretKey& mfSecretKey, ZZX& logg, Context& context);

	/**
	 * @brief gadget decryption MFCiphertext into polynomial vector 
	 * 
	 * @param Gamma: gadget encryption result MFCiphertext 
	 * @param mfSecretKey 
	 * @param logg: gadget vector of logarithmic elements  
	 * @param context 
	 * @return vector<ZZX> 
	 */
	vector<ZZX> gadgetDecryption(MFCiphertext& Gamma, MFSecretKey& mfSecretKey, ZZX& logg, Context& context);
	
	/**
	 * decrypts MFCiphertext into message
	 * @param[in] secretKey: secret key
	 * @param[in] cipher: MFCiphertext
	 * @return message
	 */
	MFPlaintext decryptMsg(MFSecretKey& mfSecretKey, MFCiphertext& cipher);

	/**
	 * partially decrypts MFCiphertext into partical decryption result (MFCiphertext)
	 * @param[in] mfSecretKey: secret key
	 * @param[in] cipher: MFCiphertext
	 * @return message
	 */
	MFCiphertext partDecryptMsg(ZZX sx, MFCiphertext& cipher, long party_id);

	/**
	 * fully decrypts MFCiphertext into message
	//  * @param[in] cipher: MFCiphertext
	 * @param[in] cipher1: partical decryption result (MFCiphertext)
	 * @param[in] cipher2: partical decryption result (MFCiphertext)
	 * @return message
	 */
	MFPlaintext fullDecryptMsg(MFCiphertext& cipher1, MFCiphertext& cipher2);

	/**
	 * encodes an array of double values into message and then encrypts it into MFCiphertext using public key encyption
	 * @param[in] vals: array of double values
	 * @param[in] slots: array size
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MFCiphertext encrypt(double* vals, long slots, long logp, long logq);

	/**
	 * encodes an array of complex values into message and then encrypts it into MFCiphertext using public key encyption
	 * @param[in] vals: array of complex values
	 * @param[in] slots: array size
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MFCiphertext encrypt(complex<double>* vals, long slots, long logp, long logq);

	/**
	 * encodes an array of 0 values into message and then encrypts it into MFCiphertext using public key encyption
	 * @param[in] vals: array of 0 values
	 * @param[in] slots: array size
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MaskResults maskEncrypt(MFSecretKey mfSecretKey, ZZX vx, complex<double>* vals, ZZX logg, long slots, long logp, long logq);
	MaskResults maskEncrypt(MFSecretKey mfSecretKey, ZZX vx, ZZX mx, ZZX logg, long slots, long logp, long logq);

	/**
	 * @brief extends gadget encryption result
	 * 
	 * @param Gamma: gadget encryption result MFCiphertext  
	 * @param logg 
	 * @param bx 
	 * @param bxx 
	 * @return MFCiphertext = Gamma \boxdot (bxx-bx) 
	 */
	MFCiphertext maskExtend(MFCiphertext& Gamma, ZZX& logg, ZZX& bx, ZZX& bxx);

	/**
	 * @brief external product between a polynomial and a gadget encryption result
	 * 
	 * @param ax 
	 * @param U 
	 * @param logg 
	 * @param context 
	 * @return MFCiphertext 
	 */
	MFCiphertext externalProduct(ZZX& ax, GadgetEncryption& U, ZZX& logg, Context& context);

	/**
	 * @brief verify whether external product is correct
	 * 
	 * @param msg 
	 * @param mfSecretKey 
	 * @param ax 
	 * @param Gamma 
	 * @param logg 
	 * @param context 
	 * @return true 
	 * @return false 
	 */
	bool verifyExternalProduct(MFPlaintext& msg, MFSecretKey& mfSecretKey, ZZX& ax, MFCiphertext& Gamma, ZZX& logg, Context& context);

	/**
	 * @brief gadget decompose of polynomial into polynomial vectors
	 * 
	 * @param ax 
	 * @param logg 
	 * @param context 
	 * @return vector<ZZX> 
	 */
	vector<ZZX> gadgetDecompose(ZZX ax, ZZX& logg, Context context);

	/**
	 * @brief verify whether gadget decomposition is correct
	 * 
	 * @param ax: polynomial 
	 * @param H: gadget decomposition mapping
	 * @param logg: gadget vector of logarithmic elements
	 * @param context 
	 * @return true: verification successful 
	 * @return false 
	 */
	bool verifyDecomposition(ZZX ax, vector<ZZX>& H, ZZX& logg, Context context);


	/**
	 * encodes an array of zeros into message and then encrypts it into MFCiphertext using public key encyption
	 * @param[in] slots: array size
	 * @param[in] logp: log of message quantize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MFCiphertext encryptZeros(long slots, long logp, long logq);

	/**
	 * decrypts MFCiphertext into message and then decodes it into array of complex values
	 * @param[in] secretKey: secret key
	 * @param[in] cipher: MFCiphertext
	 * @return decrypted array of complex values
	 */
	complex<double>* decrypt(MFSecretKey& secretKey, MFCiphertext& cipher);

	/**
	 * Partially decrypts MFCiphertext into partial decryption result (MFCiphertext)
	 * @param[in] mfSecretKey: secret key
	 * @param[in] cipher: MFCiphertext
	 * @return partial decryption result (MFCiphertext)
	 */
	MFCiphertext partDecrypt(ZZX sx, MFCiphertext& cipher, long party_id);	

	/**
	 * Fully decrypts MFCiphertext into message and then decodes it into array of complex values
	 * @param[in] ciper: MFCiphertext
	 * @param[in] ciper1: partial decryption result (MFCiphertext)
	 * @param[in] cipher2: partial decryption result (MFCiphertext)
	 * @return decrypted array of complex values
	 */
	complex<double>* fullDecrypt(MFCiphertext& cipher1, MFCiphertext& cipher2);	


	/**
	 * encodes single double value into a message and then encrypts it into a MFCiphertext using public key encyption
	 * @param[in] val: double value
	 * @param[in] logq: log of message quntize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MFCiphertext encryptSingle(double val, long logp, long logq);

	/**
	 * encodes a single complex value into a message and then encrypts it into a MFCiphertext using public key encyption
	 * @param[in] val: complex value
	 * @param[in] logq: log of message quntize value
	 * @param[in] logq: log of MFCiphertext modulus
	 * @return MFCiphertext
	 */
	MFCiphertext encryptSingle(complex<double> val, long logp, long logq);

	/**
	 * decrypts MFCiphertext into message and then decodes it into a single complex value
	 * @param[in] secretKey: secret key
	 * @param[in] cipher: MFCiphertext
	 * @return decrypted complex value
	 */
	complex<double> decryptSingle(MFSecretKey& secretKey, MFCiphertext& cipher);


	//----------------------------------------------------------------------------------
	//   HOMOMORPHIC OPERATIONS
	//----------------------------------------------------------------------------------


	/**
	 * negate the MFCiphertext
	 * @param[in] cipher: MFCiphertext(m)
	 * @return MFCiphertext(-m)
	 */
	MFCiphertext negate(MFCiphertext& cipher);

	/**
	 * negate the MFCiphertext
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(-m)
	 */
	void negateAndEqual(MFCiphertext& cipher);

	/**
	 * @brief addition of MFCiphertexts
	 * 
	 * @param cipher1 : MFCiphertext(m1)
	 * @param cipher2 : MFCiphertext(m2)
	 * @param MR1 : masking 
	 * @param MR2 : masking
	 * @return MFCiphertext(m1 + m2)
	 */
	MFCiphertext add(MFCiphertext& cipher1, MFCiphertext& cipher2, MaskResults& MR1, MaskResults& MR2);

	/**
	 * addition of MFCiphertexts
	 * @param[in, out] cipher1: MFCiphertext(m1) -> MFCiphertext(m1 + m2)
	 * @param[in] cipher2: MFCiphertext(m2)
	 * @param MR1 : masking 
	 * @param MR2 : masking
	 */
	void addAndEqual(MFCiphertext& cipher1, MFCiphertext& cipher2, MaskResults& MR1, MaskResults& MR2);


	/**
	 * multiplication of MFCiphertexts. This algorithm contain relinearization.
	 * To manage the noise we usually need rescaling method after multiplication
	 * @param[in] cipher1: MFCiphertext(m1)
	 * @param[in] cipher2: MFCiphertext(m2)
	 * @return MFCiphertext(m1 * m2)
	 */
	MFCiphertext mult(MFCiphertext& cipher1, MFCiphertext& cipher2);

	/**
	 * multiplication of MFCiphertexts. This algorithm contain relinearization.
	 * To manage the noise we usually need rescaling method after multiplication
	 * @param[in, out] cipher1: MFCiphertext(m1) -> MFCiphertext(m1 * m2)
	 * @param[in] cipher2: MFCiphertext(m2)
	 */
	void multAndEqual(MFCiphertext& cipher1, MFCiphertext& cipher2);

	/**
	 * squaring a MFCiphertext. This algorithm contain relinearization.
	 * To manage the noise we usually need resclaing method after squaring
	 * @param[in] cipher: MFCiphertext(m)
	 * @return MFCiphertext(m^2)
	 */
	MFCiphertext square(MFCiphertext& cipher);

	/**
	 * squaring a MFCiphertext. This algorithm contain relinearization.
	 * To manage the noise we usually need resclaing method after squaring
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(m^2)
	 */
	void squareAndEqual(MFCiphertext& cipher);

	/**
	 * quantized constant multiplication
	 * @param[in, out] cipher: MFCiphertext(m)
	 * @param[in] cnst: constant
	 * @param[in] logp: number of quantized bits
	 * @return MFCiphertext(m * (cnst * 2^logp))
	 */
	MFCiphertext multByConst(MFCiphertext& cipher, double cnst, long logp);

	/**
	 * quantized constant multiplication
	 * @param[in, out] cipher: MFCiphertext(m)
	 * @param[in] cnst: constant
	 * @param[in] logp: number of quantized bits
	 * @return MFCiphertext(m * (cnst * 2^logp))
	 */
	MFCiphertext multByConst(MFCiphertext& cipher, RR& cnst, long logp);

	/**
	 * quantized constant multiplication
	 * @param[in, out] cipher: MFCiphertext(m)
	 * @param[in] cnst: constant
	 * @param[in] logp: number of quantized bits
	 * @return MFCiphertext(m * (cnst * 2^logp))
	 */
	MFCiphertext multByConst(MFCiphertext& cipher, complex<double> cnst, long logp);

	
	//----------------------------------------------------------------------------------
	//   RESCALING & MODULUS DOWN
	//----------------------------------------------------------------------------------


	/**
	 * rescaling procedure
	 * @param[in] cipher: MFCiphertext(m)
	 * @param[in] bitsDown: rescaling bits
	 * @return MFCiphertext(m / 2^bitsDown) with new modulus (q / 2^bitsDown)
	 */
	MFCiphertext reScaleBy(MFCiphertext& cipher, long bitsDown);

	/**
	 * rescaling procedure
	 * @param[in] cipher: MFCiphertext(m)
	 * @param[in] newlogq: log of new MFCiphertext modulus
	 * @return MFCiphertext(m / 2^(logq - newlogq)) with new modulus (2^newlogq)
	 */
	MFCiphertext reScaleTo(MFCiphertext& cipher, long newlogq);

	/**
	 * rescaling procedure
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(m / 2^bitsDown) with new modulus (q / 2^bitsDown)
	 * @param[in] bitsDown: rescaling bits
	 */
	void reScaleByAndEqual(MFCiphertext& cipher, long bitsDown);

	/**
	 * rescaling procedure
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(m / 2^(logq - newlogq)) with new modulus (2^newlogq)
	 * @param[in] newlogq: log ofnew MFCiphertext modulus
	 */
	void reScaleToAndEqual(MFCiphertext& cipher, long newlogq);

	/**
	 * modulus down procedure
	 * @param[in] cipher: MFCiphertext(m)
	 * @param[in] bitsDown: modulus down bits
	 * @return MFCiphertext(m) with new modulus (q/2^bitsDown)
	 */
	MFCiphertext modDownBy(MFCiphertext& cipher, long bitsDown);

	/**
	 * modulus down procedure
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(m) with new modulus (q/2^bitsDown)
	 * @param[in] bitsDown: modulus down bits
	 */
	void modDownByAndEqual(MFCiphertext& cipher, long bitsDown);

	/**
	 * modulus down procedure
	 * @param[in] cipher: MFCiphertext(m)
	 * @param[in] newlogq: log of new MFCiphertext modulus
	 * @return MFCiphertext(m) with new modulus (2^newlogq)
	 */
	MFCiphertext modDownTo(MFCiphertext& cipher, long newlogq);

	/**
	 * modulus down procedure
	 * @param[in, out] cipher: MFCiphertext(m) -> MFCiphertext(m) with new modulus (2^newlogq)
	 * @param[in] newlogq: log of new MFCiphertext modulus
	 */
	void modDownToAndEqual(MFCiphertext& cipher, long newlogq);


	//----------------------------------------------------------------------------------
	//   ROTATIONS & CONJUGATIONS
	//----------------------------------------------------------------------------------


	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots))
	 * @param[in] logRotSlots: log of rotation slots
	 * @return MFCiphertext(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 */
	MFCiphertext leftRotateByPo2(MFCiphertext& cipher, long logRotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in, out] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots)) -> cipher(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 * @param[in] logRotSlots: log of rotation slots
	 */
	void leftRotateByPo2AndEqual(MFCiphertext& cipher, long logRotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots))
	 * @param[in] logRotSlots: log of rotation slots
	 * @return MFCiphertext(m(v_{1-rotSlots}, v_{2-rotSlots}, ..., v_{slots-rotSlots})
	 */
	MFCiphertext rightRotateByPo2(MFCiphertext& cipher, long logRotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in, out] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots)) -> cipher(m(v_{1-rotSlots}, v_{2-rotSlots}, ..., v_{slots-rotSlots})
	 * @param[in] logRotSlots: log of rotation slots
	 */
	void rightRotateByPo2AndEqual(MFCiphertext& cipher, long logrotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots))
	 * @param[in] logRotSlots: log of rotation slots
	 * @return MFCiphertext(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 */
	MFCiphertext leftRotateFast(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in, out] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots)) -> cipher(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 * @param[in] logRotSlots: log of rotation slots
	 */
	void leftRotateAndEqualFast(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots))
	 * @param[in] rotSlots: rotation slots
	 * @return MFCiphertext(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 */
	MFCiphertext leftRotate(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in, out] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots)) -> cipher(m(v_{1+rotSlots}, v_{2+rotSlots}, ..., v_{slots+rotSlots})
	 * @param[in] rotSlots: rotation slots
	 */
	void leftRotateAndEqual(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots))
	 * @param[in] rotSlots: rotation slots
	 * @return MFCiphertext(m(v_{1-rotSlots}, v_{2-rotSlots}, ..., v_{slots-rotSlots})
	 */
	MFCiphertext rightRotate(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of array with rotated indexes
	 * @param[in, out] cipher: MFCiphertext(m(v_1, v_2, ..., v_slots)) -> cipher(m(v_{1-rotSlots}, v_{2-rotSlots}, ..., v_{slots-rotSlots})
	 * @param[in] rotSlots: rotation slots
	 */
	void rightRotateAndEqual(MFCiphertext& cipher, long rotSlots);

	/**
	 * calculates MFCiphertext of conjugations
	 * @param[in] cipher: MFCiphertext(m = x + iy)
	 * @return MFCiphertext(x - iy)
	 */
	MFCiphertext conjugate(MFCiphertext& cipher);

	/**
	 * calculates MFCiphertext of conjugations
	 * @param[in, out] cipher: MFCiphertext(m = x + iy) -> MFCiphertext(x - iy)
	 */
	void conjugateAndEqual(MFCiphertext& cipher);

};

#endif
