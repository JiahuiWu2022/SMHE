/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef MFHE_MFCIPHERTEXT_H_
#define MFHE_MFCIPHERTEXT_H_

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <vector>
#include <stdexcept>

using namespace std;
using namespace NTL;

/**
 * Ciphertext 表示一个 RLWE 实例，在环 Z_q[X]/(X^N+1) 中
 * 原始密文以非扩展形式存储为 (ax, bx).
 * 扩展操作将密文转换为多密钥形式：
 *   - ax 保持不变；
 *   - bx 扩展为一个长度为 1+num_parties 的向量，其中在下标 party_id 处存放原始 bx (expanded_bx[party_id] = 原始 bx)，
 *     其余位置填充零多项式。
 * Gadget Encryption: 将密文扩展为Gadget Encryption密文形式，即：
 *   扩展后密文为 (expanded_ax, expanded_bx)
 *   其中 expanded_ax 和 expanded_bx 均为长度为 tau 的向量。
 */
class MFCiphertext {
public:

	// 使用 vector<ZZX> 存储密文多项式
	vector<ZZX> ax;        
    vector<ZZX> bx;        // bx 的存储方式：
                           //  - 非扩展时，bx.size() == 1
                           //  - 扩展后 bx.size() == 1+num_parties
    long logp;             // 量化位数
    long logq;             // 模数的比特数
    long slots;            // 密文中槽的数量
    bool isComplex;        // 是否采用单实数槽
	long party_id;

	//-----------------------------------------

	/**
     * 非扩展密文的构造函数
     * @param a: 多项式 ax
     * @param b: 多项式 bx
     * @param logp: 量化位数
     * @param logq: 模数的比特数
     * @param slots: 密文槽数量
     * @param isComplex: 是否采用单实数槽
     */
    MFCiphertext(const ZZX& a = ZZX::zero(), const ZZX& b = ZZX::zero(), 
               long logp = 0, long logq = 0, long slots = 1, bool isComplex = true, long party_id = 0)
        : logp(logp), logq(logq), slots(slots), isComplex(isComplex), party_id(party_id) {
        ax.push_back(a), bx.push_back(b); // 非扩展时，ax,bx 仅包含一个元素
    }

    /**
     * 扩展密文的构造函数，直接传入扩展后的 ax 向量
     */
    MFCiphertext(const vector<ZZX>& ax, const ZZX& b, 
                long logp, long logq, long slots, bool isComplex = true, long party_id = 0)
         : ax(ax), logp(logp), logq(logq), slots(slots), isComplex(isComplex), party_id(party_id) {
         bx.push_back(b);
    }    

    /**
     * Gadget Encryption扩展密文的构造函数，直接传入扩展后的 ax,bx 向量
     */
    MFCiphertext(const vector<ZZX>& ax, const vector<ZZX>& bx, 
               long logp, long logq, long slots, bool isComplex = true, long party_id = 0)
        : ax(ax), bx(bx), logp(logp), logq(logq), slots(slots), isComplex(isComplex), party_id(party_id) {}	


    MFCiphertext(const MFCiphertext& o)
        : ax(o.ax), bx(o.bx), logp(o.logp), logq(o.logq), slots(o.slots), isComplex(o.isComplex), party_id(o.party_id) {}

    /**
     * 将非扩展密文扩展为多密钥密文。
     * 扩展规则：
     *   - 保持 ax 不变；
     *   - bx 扩展为长度为 1+num_parties 的向量，其中在下标 party_id 处存放原始 bx（即 bx[0]），其它位置填充零多项式。
     *
     * 例如，对于 party_id = 5 且 num_parties = 8，
     * 扩展后得到的 bx 为：
     *   (0, 0, 0, 0, 0, original_bx, 0, 0, 0)
     *
     * @param party_id: 指定 bx 存放原始 bx 的位置，取值范围 [1, num_parties]
     * @param num_parties: 系统中总的参与方数
     * @return 扩展后的 MFCiphertext 对象
     */
    MFCiphertext expand(int party_id, int num_parties) const {
        if (party_id < 1 || party_id > num_parties)
            throw invalid_argument("party_id must be in the range [1, num_parties].");

        int new_size = 1 + num_parties;
        vector<ZZX> ext_bx(new_size, ZZX::zero());
        // 将原始 bx (即 bx[0]) 放入下标 party_id 处
        ext_bx[party_id] = this->bx[0];
        
        // ax 保持不变，返回扩展后的密文
        return MFCiphertext(this->ax, ext_bx, this->logp, this->logq, this->slots, this->isComplex, this->party_id);
    }

    /**
     * 将非扩展密文(ax,bx)扩展为Gadget Encryption密文(u0,u1)\in R_{Q}^{\tau\times 2}。
     * 扩展规则：
     *   - ax 扩展为长度为 \tau 的向量；
     *   - bx 扩展为长度为 \tau 的向量。
     *
     * @param tau: 指定 ax,bx 长度
     * @return 扩展后的 MFCiphertext 对象
     */
    MFCiphertext expand(int tau) const {
        vector<ZZX> ext_ax(tau, ZZX::zero());
        vector<ZZX> ext_bx(tau, ZZX::zero());
        
        // 返回扩展后的密文
        return MFCiphertext(ext_ax, ext_bx, this->logp, this->logq, this->slots, this->isComplex, this->party_id);
    }

};

#endif


/*
代码说明
非扩展构造函数
采用 ax 为单个多项式，bx 为单一元素的向量。这样保持与CKKS原始密文结构一致。

expand 方法

检查 party_id 是否在合法范围内（[1, num_parties]）。

创建长度为 1+num_parties 的新向量 ext_bx，所有元素初始化为零多项式。

将原始的 bx[0] 放置在 ext_bx[party_id] 位置，其它位置保持为零。

返回新的 Ciphertext 对象，新对象中的 ax 保持不变，而 bx 为扩展后的向量。

这样，对于例如原始密文 ct₅ = (ax₅, bx₅)（其中 bx₅ 存储在 bx[0] 中），调用
Ciphertext ext_ct = ct5.expand(5, 8);

将得到扩展后的密文\bar{ct}=(ax_5,0,0,0,0,bx_5,0,0,0)
*/
