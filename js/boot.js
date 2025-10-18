// js/boot.js
import { ethers } from 'https://esm.sh/ethers@6.13.2';
import { Client as XMTPClient } from 'https://esm.sh/@xmtp/xmtp-js@11.5.0';

window.ethers = ethers;
window.XMTP = { Client: XMTPClient };
