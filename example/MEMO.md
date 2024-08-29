# MEMO

- https://chaldene.net/erc721

## ERC721

- ERC721 is a specification for NFT (Non Fungible Token), where each token cannot be exchanged.

- When contructing a contract that follows ERC721, we need to implement `interface` based on ERC721 and ERC165. Note that ERC165 is a specification that implements `interface` and checks whether a contract has `interface`.

### Event

ERC721 has the following three events.

- `transfer`: Emitted when `tokenId` token is transferred from `from` to `to`.
- `Approval`: Emitted when `owner` enables `approved` to manage the `tokenId` token.
- `ApprovalForAll`: itted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.

### Function

- `function balanceOf(address _owner) external view returns (uint256);`: Returns the number of all NFTs that belong to `_owner`.
- `function ownerOf(uint256 _tokenId) external view returns (address);`: Returns the address of the owner that has the NFT whose ID is `_tokenID`.