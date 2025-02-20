// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    //----------------------------------------------------------------------//
    //                                ERRORS                                //
    //----------------------------------------------------------------------//
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes result);
    //----------------------------------------------------------------------//
    //                           STATE VARIABLES                            //
    //----------------------------------------------------------------------//

    IEntryPoint private immutable i_entryPoint;

    //----------------------------------------------------------------------//
    //                              MODIFIERS                               //
    //----------------------------------------------------------------------//
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    //----------------------------------------------------------------------//
    //                              FUNCTIONS                               //
    //----------------------------------------------------------------------//
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}
    //----------------------------------------------------------------------//
    //                          EXTERNAL FUNCTIONS                          //
    //----------------------------------------------------------------------//

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        // _validateNonce() we should probably do some nonce validation but the entry point is taking care of it.
        //we need to hava a _payPrefund function where we actually pay the entry point contract
        _payPrefund(missingAccountFunds);
    }

    function execute(address dest, uint256 value, bytes calldata functionData) external {
        //this is where we are going to execute the user operation
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    //----------------------------------------------------------------------//
    //                          INTERNAL FUNCTIONS                          //
    //----------------------------------------------------------------------//

    //userophash is going to be the EIP191 version of the signed hash. In this function is where we are saying make sure google signed this message or make sure 3 of 5 multisig signed this message etc.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    //----------------------------------------------------------------------//
    //                               GETTERS                                //
    //----------------------------------------------------------------------//

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
