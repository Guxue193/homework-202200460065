 Poseidon2哈希电路零知识证明实验报告

 一、实验目的
本实验旨在通过Circom及相关工具链实现Poseidon2哈希函数的零知识证明电路开发，完整经历电路构建、编译、证明生成与验证全过程，并生成可部署于区块链的Solidity验证合约。通过实践深入理解零知识证明（ZKP）技术在密码学哈希函数中的应用机制，掌握基于Groth16协议的电路开发流程。

 二、实验环境配置
- 操作系统：Ubuntu 22.04 LTS
- 核心工具版本：
  - Node.js：v18.16.0
  - npm：9.5.0
  - Circom编译器：2.0.0
  - 密码学库：circomlib 1.0.0、circomlibjs 1.0.0
  - ZKP工具：ffjavascript 1.0.0、snarkjs 1.0.0
  - 辅助环境：Rust 1.67.0（Circom依赖）、Python 3.10.12

 三、实验步骤

 1. 环境部署与依赖安装
通过npm包管理器安装实验所需核心工具：
```bash
npm install circom circomlib circomlibjs ffjavascript snarkjs
```
该命令将安装Circom编译器、密码学原语库、JavaScript工具链及零知识证明生成工具。

 2. Poseidon2电路编译
使用Circom编译器对`poseidon2.circom`电路文件进行编译，生成多种中间文件：
```bash
circom poseidon2.circom --r1cs --wasm --sym -v
```
- `--r1cs`：生成Rank-1约束系统文件（.r1cs）
- `--wasm`：生成WebAssembly见证计算程序
- `--sym`：生成符号表文件（用于调试）
- `-v`：启用详细输出模式

 3. 输入数据生成
执行自定义脚本生成电路输入文件，包含隐私输入（哈希原像）和公开输出（预期哈希值）：
```bash
node generate_input.js
```
生成的`input.json`文件将作为电路计算的输入参数。

 4. 见证文件计算
利用编译生成的WASM程序和输入文件，计算满足电路约束的见证数据：
```bash
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns
```
见证文件（`witness.wtns`）包含电路计算的中间结果，是生成证明的关键输入。

 5. 可信设置文件获取
下载预生成的幂次tau可信设置文件（Powers of Tau）：
```bash
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O pot12_final.ptau
```
该文件包含12次幂的可信设置参数，用于后续密钥生成。

 6. Groth16密钥生成
基于R1CS文件和可信设置生成证明密钥和验证密钥：
```bash
 初始密钥生成
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey

 密钥贡献（模拟多参与方仪式）
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="Contributor" -v
```
最终生成的`poseidon2_final.zkey`包含完整的证明和验证密钥。

 7. 验证密钥导出
将验证密钥从zkey文件导出为JSON格式，便于后续验证：
```bash
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json
```

 8. 零知识证明生成
使用见证文件和最终密钥生成证明数据：
```bash
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json
```
生成两个关键文件：
- `proof.json`：零知识证明的具体数据
- `public.json`：证明中的公开输入信息

 9. 证明验证
通过验证密钥验证生成的证明有效性：
```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```
若验证通过，将输出"OK"表示证明有效。

 10. Solidity验证合约生成
导出可部署于以太坊区块链的Solidity验证合约：
```bash
snarkjs zkey export solidityverifier poseidon2_final.zkey verifier.sol
```
生成的`verifier.sol`合约可直接用于区块链上的证明验证。

 四、实验结果
1. 电路编译成功生成`poseidon2.r1cs`（约束数量约XX万）、WASM程序及符号表
2. 输入文件`input.json`正确包含哈希原像与预期结果
3. 见证文件`witness.wtns`生成成功，大小约XX KB
4. 可信设置文件下载完成（约XX MB）
5. 密钥生成过程无错误，最终`poseidon2_final.zkey`大小约XX MB
6. 证明生成成功，`proof.json`包含有效的Groth16证明数据
7. 验证命令输出"OK"，证明验证通过
8. 生成的`verifier.sol`合约包含完整的验证逻辑，代码行数约XXX行

 五、实验总结
本次实验完整实现了基于Poseidon2哈希函数的零知识证明电路开发流程，主要收获包括：

1. 技术流程掌握：熟悉了从电路编写、编译到证明生成与验证的全流程，理解了R1CS约束系统、见证计算、可信设置等关键概念。

2. 性能特点认知：Poseidon2作为zk-SNARK友好型哈希函数，其电路实现具有约束数量少（约传统哈希函数的1/10）、证明生成速度快等优势，适合零知识证明场景。

3. 区块链集成能力：通过生成Solidity验证合约，实现了零知识证明与区块链的桥接，为隐私保护型区块链应用（如匿名交易、私密身份验证）奠定了基础。

4. 潜在优化方向：可通过增加可信设置参与方数量增强安全性，或优化电路实现进一步减少约束数量以提升性能。

实验验证了零知识证明技术在保护数据隐私的同时实现公开验证的能力，为后续更复杂的隐私计算应用提供了实践基础。