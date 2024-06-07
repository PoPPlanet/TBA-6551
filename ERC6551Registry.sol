// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {IERC6551Registry} from '../../interfaces/IERC6551Registry.sol';
import {IERC6551Account} from '../../interfaces/IERC6551Account.sol';
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import {IERC721} from '@openzeppelin/contracts/token/ERC721/IERC721.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

contract ERC6551Registry is IERC6551Registry, EIP712Upgradeable {

    address public verifyAddress;
    address public governance;
    mapping(address => bool) public creator;
    //erc20 => id => amount
    mapping(address => mapping(uint256 => uint256)) private ids;
    //erc20 => claimedTotalAmount
    mapping(address => uint256) public claimedTotalAmount;
    //tba => erc20 => claimedTotalAmount
    mapping(address => mapping(address => uint256)) public tbaClaimedTotalAmount;


    bytes32 private constant TYPEHASH =
    keccak256(
        "VerifyRequest(uint256 id,uint256 validityStartTimestamp,uint256 validityEndTimestamp,uint256 amount,address receiptTbaAddress,address erc20Address)"
    );

    struct VerifyRequest {
        uint256 id;
        uint256 validityStartTimestamp;
        uint256 validityEndTimestamp;
        uint256 amount;
        address payable receiptTbaAddress;
        address erc20Address;
    }

    event Claimed(
        address msgSender,
        address receiptTbaAddress,
        address receiptAddress,
        uint256 id,
        uint256 amount,
        address erc20Address
    );

    constructor (address _verifyAddress) initializer {
        __EIP712_init('ClaimTokenWithSignature', "1");
        verifyAddress = _verifyAddress;
        governance = msg.sender;
    }

    function createAccount(
        address implementation,
        bytes32 salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) external returns (address payable) {
        require(creator[msg.sender], 'Invalid creator');
        assembly {
        // Memory Layout:
        // ----
        // 0x00   0xff                           (1 byte)
        // 0x01   registry (address)             (20 bytes)
        // 0x15   salt (bytes32)                 (32 bytes)
        // 0x35   Bytecode Hash (bytes32)        (32 bytes)
        // ----
        // 0x55   ERC-1167 Constructor + Header  (20 bytes)
        // 0x69   implementation (address)       (20 bytes)
        // 0x5D   ERC-1167 Footer                (15 bytes)
        // 0x8C   salt (uint256)                 (32 bytes)
        // 0xAC   chainId (uint256)              (32 bytes)
        // 0xCC   tokenContract (address)        (32 bytes)
        // 0xEC   tokenId (uint256)              (32 bytes)

        // Silence unused variable warnings
            pop(chainId)

        // Copy bytecode + constant data to memory
            calldatacopy(0x8c, 0x24, 0x80) // salt, chainId, tokenContract, tokenId
            mstore(0x6c, 0x5af43d82803e903d91602b57fd5bf3) // ERC-1167 footer
            mstore(0x5d, implementation) // implementation
            mstore(0x49, 0x3d60ad80600a3d3981f3363d3d373d3d3d363d73) // ERC-1167 constructor + header

        // Copy create2 computation data to memory
            mstore(0x35, keccak256(0x55, 0xb7)) // keccak256(bytecode)
            mstore(0x15, salt) // salt
            mstore(0x01, shl(96, address())) // registry address
            mstore8(0x00, 0xff) // 0xFF

        // Compute account address
            let computed := keccak256(0x00, 0x55)

        // If the account has not yet been deployed
            if iszero(extcodesize(computed)) {
            // Deploy account contract
                let deployed := create2(0, 0x55, 0xb7, salt)

            // Revert if the deployment fails
                if iszero(deployed) {
                    mstore(0x00, 0x20188a59) // `AccountCreationFailed()`
                    revert(0x1c, 0x04)
                }

            // Store account address in memory before salt and chainId
                mstore(0x6c, deployed)

            // Emit the ERC6551AccountCreated event
                log4(
                0x6c,
                0x60,
                // `ERC6551AccountCreated(address,address,bytes32,uint256,address,uint256)`
                0x79f19b3655ee38b1ce526556b7731a20c8f218fbda4a3990b6cc4172fdf88722,
                implementation,
                tokenContract,
                tokenId
                )

            // Return the account address
                return(0x6c, 0x20)
            }

        // Otherwise, return the computed account address
            mstore(0x00, shr(96, shl(96, computed)))
            return(0x00, 0x20)
        }
    }

    function account(
        address implementation,
        bytes32 salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) external view returns (address) {
        assembly {
        // Silence unused variable warnings
            pop(chainId)
            pop(tokenContract)
            pop(tokenId)

        // Copy bytecode + constant data to memory
            calldatacopy(0x8c, 0x24, 0x80) // salt, chainId, tokenContract, tokenId
            mstore(0x6c, 0x5af43d82803e903d91602b57fd5bf3) // ERC-1167 footer
            mstore(0x5d, implementation) // implementation
            mstore(0x49, 0x3d60ad80600a3d3981f3363d3d373d3d3d363d73) // ERC-1167 constructor + header

        // Copy create2 computation data to memory
            mstore(0x35, keccak256(0x55, 0xb7)) // keccak256(bytecode)
            mstore(0x15, salt) // salt
            mstore(0x01, shl(96, address())) // registry address
            mstore8(0x00, 0xff) // 0xFF

        // Store computed account address in memory
            mstore(0x00, shr(96, shl(96, keccak256(0x00, 0x55))))

        // Return computed account address
            return(0x00, 0x20)
        }
    }

    function setCreator(address _creator, bool _create) public {
        require(msg.sender == governance, 'Not governance');
        creator[_creator] = _create;
    }

    function changeVerifyAddress(address _newVerifyAddress) public {
        require(msg.sender == governance, 'Not governance');
        verifyAddress = _newVerifyAddress;
    }

    function claim(VerifyRequest calldata _req, bytes calldata _signature) public {
        require(ids[_req.erc20Address][_req.id] == 0, "Invalid id");
        require(verifyRequest(_req, _signature), "Invalid signature");
        (, address tokenContract, uint256 tokenId) = IERC6551Account(_req.receiptTbaAddress).token();
        address nftOwner = IERC721(tokenContract).ownerOf(tokenId);
        require(nftOwner != address(0), 'NFT owner is address 0.');
        IERC20(_req.erc20Address).transfer(nftOwner, _req.amount);
        ids[_req.erc20Address][_req.id] = _req.amount;
        claimedTotalAmount[_req.erc20Address] += _req.amount;
        tbaClaimedTotalAmount[_req.receiptTbaAddress][_req.erc20Address] += _req.amount;
        emit Claimed(msg.sender, _req.receiptTbaAddress, nftOwner, _req.id, _req.amount, _req.erc20Address);
    }

    function checkId(address _erc20Address, uint256 _id) public view returns(uint256) {
        return ids[_erc20Address][_id];
    }

    function verifyRequest(VerifyRequest calldata _req, bytes calldata _signature) public view returns (bool) {
        require(_req.validityStartTimestamp <= block.timestamp && _req.validityEndTimestamp >= block.timestamp, "request expired");
        address signer = recoverAddress(_req, _signature);
        return signer == verifyAddress;
    }

    function recoverAddress(VerifyRequest calldata _req, bytes calldata _signature) private view returns (address) {
        return ECDSAUpgradeable.recover(_hashTypedDataV4(keccak256(_encodeRequest(_req))), _signature);
    }

    function _encodeRequest(VerifyRequest calldata _req) private pure returns (bytes memory) {
        return
        abi.encode(
            TYPEHASH,
            _req.id,
            _req.validityStartTimestamp,
            _req.validityEndTimestamp,
            _req.amount,
            _req.receiptTbaAddress,
            _req.erc20Address
        );
    }
}
