pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IERC6551Account} from '../../interfaces/IERC6551Account.sol';
import {IERC6551Executable} from '../../interfaces/IERC6551Executable.sol';

contract ERC6551Account is IERC165, IERC1271, IERC6551Account, IERC6551Executable, IERC1155Receiver, IERC721Receiver {
    uint256 public state;

    receive() external payable {}

    function execute(address to, uint256 value, bytes calldata data, uint8 operation)
    external
    payable
    virtual
    returns (bytes memory result)
    {
        require(_isValidSigner(msg.sender), "Invalid signer");
        require(operation == 0, "Only call operations are supported");

        ++state;

        bool success;
        (success, result) = to.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function isValidSigner(address signer, bytes calldata) external view virtual returns (bytes4) {
        if (_isValidSigner(signer)) {
            return IERC6551Account.isValidSigner.selector;
        }

        return bytes4(0);
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
    external
    view
    virtual
    returns (bytes4 magicValue)
    {
        bool isValid = SignatureChecker.isValidSignatureNow(owner(), hash, signature);

        if (isValid) {
            return IERC1271.isValidSignature.selector;
        }

        return bytes4(0);
    }

    function supportsInterface(bytes4 interfaceId) external pure virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId
        || interfaceId == type(IERC6551Account).interfaceId
        || interfaceId == type(IERC6551Executable).interfaceId;
    }

    function token() public view virtual returns (uint256, address, uint256) {
        bytes memory footer = new bytes(0x60);

        assembly {
            extcodecopy(address(), add(footer, 0x20), 0x4d, 0x60)
        }

        return abi.decode(footer, (uint256, address, uint256));
    }

    function owner() public view virtual returns (address) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = token();
        if (chainId != block.chainid) return address(0);

        return IERC721(tokenContract).ownerOf(tokenId);
    }

    function _isValidSigner(address signer) internal view virtual returns (bool) {
        return signer == owner();
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4){
        return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    }

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external override returns (bytes4){
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external override returns (bytes4){
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }

    function batchTransferERC20(address[] calldata erc20Addresses, address payable to) public {
        require(_isValidSigner(msg.sender), "Invalid signer");
        for(uint i=0;i<erc20Addresses.length;i++){
            address erc20Address = erc20Addresses[i];
            if (erc20Address == address(0)){
                to.send(address(this).balance);
            } else {
                IERC20(erc20Address).transfer(to, IERC20(erc20Address).balanceOf(address(this)));
            }
        }
    }

    function batchTransferERC721(address[] calldata erc721Addresses, uint256[] calldata ids, address to) public {
        require(_isValidSigner(msg.sender), "Invalid signer");
        require(erc721Addresses.length == ids.length, 'Invalid params');
        for(uint i=0;i<erc721Addresses.length;i++){
            address erc721Address = erc721Addresses[i];
            IERC721(erc721Address).transferFrom(address(this), to, ids[i]);
        }
    }

    function batchTransferERC1155(address[] calldata erc1155Addresses, uint256[] calldata ids, address to) public {
        require(_isValidSigner(msg.sender), "Invalid signer");
        require(erc1155Addresses.length == ids.length, 'Invalid params');
        for(uint i=0;i<erc1155Addresses.length;i++){
            address erc1155Address = erc1155Addresses[i];
            uint256 amount = IERC1155(erc1155Address).balanceOf(address(this), ids[i]);
            IERC1155(erc1155Address).safeTransferFrom(address(this), to, ids[i], amount, '0x');
        }
    }
}
