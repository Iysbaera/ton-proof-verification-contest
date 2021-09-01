pragma ton-solidity >=0.30.0;
pragma AbiHeader pubkey;

contract VerifyGroth16 {

    bytes public m_vkey = hex"";

    function verify(bytes proof, bytes pi) public view returns (bool) {
        tvm.accept();
        string blob_str = proof;
        blob_str.append(pi);
        blob_str.append(m_vkey);
        return tvm.vergrth16(blob_str);
    }

    function setVerificationKey(bytes vkey) public {
        require(msg.pubkey() == tvm.pubkey(), 150);
        tvm.accept();
        m_vkey = vkey;
    }

}
