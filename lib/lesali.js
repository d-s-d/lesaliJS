/**
 * Created by dsd on 19/03/15.
 */

(function()
{
    var sodium = require('sodium').api;
    const _LESALI_NONCE_BYTES = 6;
    const _NONCE_INIT = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    function get_nonce(c)
    {
        var end = sodium.crypto_box_NONCEBYTES;
        var start = end - _LESALI_NONCE_BYTES;
        var res = new Buffer(_NONCE_INIT);
        for (var i = start; i < end; i++)
        {
            res[i] = (c % 256);
            c = Math.floor(c / 256);
        }
        return res;
    }

    /**
     * Reads a little-endian integer of length _LESALI_NONCE_BYTES at offset _offset and returns a Number.
     *
     * @param nonce
     * @param _offset
     * @returns {number}
     */
    function nonce_to_Number(nonce, _offset)
    {
        var offset = _offset || sodium.crypto_box_NONCEBYTES;
        var res = 0;
        for (var i = offset+_LESALI_NONCE_BYTES-1; i >= offset; i--)
        {
            res *= 256;
            res += nonce[i];
        }
        return res;
    }

    function prepare_envelope(m, p, n_cnt, offset)
    {
        if (typeof(p) === 'number' && 0 < p && p < 256)
        {
            var m_len = m.length;
            var m_p_len = m_len + p;
            var m_p = Buffer(m_p_len);

            // 32 bytes crypto_box overhead + 38 envelope
            var e_len = m_p_len + sodium.crypto_box_BOXZEROBYTES + offset + _LESALI_NONCE_BYTES;
            var e = Buffer(e_len);

            m.copy(m_p);
            for (var i = m_len; i < m_p_len; i++)
            {
                m_p[i] = p;
            }

            var nonce = get_nonce(n_cnt);
            // copy the nonce to the offset
            nonce.copy(e, offset, sodium.crypto_box_NONCEBYTES - _LESALI_NONCE_BYTES, sodium.crypto_box_NONCEBYTES);
            return [e, m_p, nonce];
        }
        else
        {
            //TODO: Meaningful exception
            throw null;
        }
    }

    function encrypt_envelope(m, p, n_cnt, pk, sk, offset)
    {
        var prep = prepare_envelope(m, p, n_cnt, offset);
        sodium.crypto_box(prep[1], prep[2], pk, sk).copy(prep[0], offset + _LESALI_NONCE_BYTES, sodium.crypto_box_BOXZEROBYTES);
        return prep[0];
    }

    function encrypt_envelope_afternm(m, p, n_cnt, k, offset)
    {
        var prep = prepare_envelope(m, p, n_cnt, offset);
        sodium.crypto_box_afternm(prep[1], prep[2], k).copy(prep[0], offset + _LESALI_NONCE_BYTES, sodium.crypto_box_BOXZEROBYTES);
        return prep[0];
    }

    function open_envelope(e, offset)
    {
        var cbox_offset = offset + _LESALI_NONCE_BYTES;
        var nonce = new Buffer(_NONCE_INIT);
        var c = Buffer(e.length - cbox_offset + sodium.crypto_box_BOXZEROBYTES);

        e.copy(nonce, sodium.crypto_box_NONCEBYTES - _LESALI_NONCE_BYTES, offset, cbox_offset);
        e.copy(c, sodium.crypto_box_BOXZEROBYTES, cbox_offset);
        for (var i = 0; i < sodium.crypto_box_BOXZEROBYTES; ++i)
        {
            c[i] = 0;
        }
        return [c, nonce];
    }

    function truncate_padding(m_p)
    {
        var p_len = m_p[m_p.length - 1];
        var m_len = m_p.length - p_len;
        if (p_len > 0 && m_len > 0)
            return m_p.slice(0, m_len);
        return -1;
    }

    function check_authenticate_and_truncate(m_p, nonce)
    {
        if (m_p)
        {
            var m = truncate_padding(m_p);
            if (m !== -1)
                return {n_cnt: nonce_to_Number(nonce), m: m};
            return -2;
        }
        return -1;
    }

    function _public_envelope_extract_pk(e)
    {
        return e.slice(0, sodium.crypto_box_PUBLICKEYBYTES);
    }

    var exports = {
        PUBLIC_ENVELOPE_MIN_LEN: 49,

        public_envelope_extract_pk: _public_envelope_extract_pk,

        public_envelope_extract_nonce: function(e)
        {
            return nonce_to_Number(e, sodium.crypto_box_PUBLICKEYBYTES);
        },

        anonymous_envelope_extract_nonce: function(e)
        {
            return nonce_to_Number(e, 0);
        },

        /**
         *
         * @param m plaintext message
         * @param p padding length
         * @param cnt message counter
         * @param pk_r public key of the receiver
         * @param keypair_s public/private key pair of the sender
         * @returns {*} buffer containing the envelope
         */
        public_envelope: function (m, p, cnt, pk_r, keypair_s)
        {
            var e = encrypt_envelope(m, p, cnt, pk_r, keypair_s.secretKey, sodium.crypto_box_PUBLICKEYBYTES);
            keypair_s.publicKey.copy(e);
            return e;
        },

        public_envelope_open: function (e, sk)
        {
            var pk = _public_envelope_extract_pk(e);
            var unsliced = open_envelope(e, sodium.crypto_box_PUBLICKEYBYTES);

            var m_p = sodium.crypto_box_open(unsliced[0], unsliced[1], pk, sk);
            return check_authenticate_and_truncate(m_p, unsliced[1]);
        },

        public_envelope_afternm: function (m, p, cnt, k, keypair_s)
        {
            var e = encrypt_envelope_afternm(m, p, cnt, k, sodium.crypto_box_PUBLICKEYBYTES);
            keypair_s.publicKey.copy(e);
            return e;
        },

        public_envelope_open_afternm: function (e, k)
        {
            var unsliced = open_envelope(e, sodium.crypto_box_PUBLICKEYBYTES);
            var m_p = sodium.crypto_box_open_afternm(unsliced[0], unsliced[1], k);
            return check_authenticate_and_truncate(m_p, unsliced[1]);
        },

        /**
         *
         * @param m plaintext message
         * @param p padding length
         * @param cnt message counter
         * @param pk_r public key of the receiver
         * @param keypair_s public/private key pair of the sender
         * @returns {*} buffer containing the envelope
         */
        anonymous_envelope: function (m, p, cnt, pk_r, keypair_s)
        {
            var e = encrypt_envelope(m, p, cnt, pk_r, keypair_s.secretKey, 0);
            return e;
        },

        anonymous_envelope_open: function (e, pk, sk)
        {
            var unsliced = open_envelope(e, 0);

            var m_p = sodium.crypto_box_open(unsliced[0], unsliced[1], pk, sk);
            return check_authenticate_and_truncate(m_p, unsliced[1]);
        },

        anonymous_envelope_afternm: function (m, p, cnt, k)
        {
            return encrypt_envelope_afternm(m, p, cnt, k, 0);
        },

        anonymous_envelope_open_afternm: function (e, k)
        {
            var unsliced = open_envelope(e, 0);
            var m_p = sodium.crypto_box_open_afternm(unsliced[0], unsliced[1], k);
            return check_authenticate_and_truncate(m_p, unsliced[1]);
        }
    };

    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined')
        module.exports = exports;
    else
        window.lesali = exports;
})();