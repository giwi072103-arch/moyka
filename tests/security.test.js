import test from 'node:test';
import assert from 'node:assert/strict';
import {signed} from './helpers.js';
import {validateTelegram,encryptCard,decryptCard,validPlate} from '../server/security.js';
test('Telegram signature verifies; rejects forgery, stale and duplicate data',()=>{
 const user={id:123,first_name:'Test'};
 assert.equal(validateTelegram(signed(user),'test-token').id,123);
 assert.throws(()=>validateTelegram(signed(user),'wrong'));
 assert.throws(()=>validateTelegram(signed(user,'test-token',1),'test-token'));
 assert.throws(()=>validateTelegram(signed(user)+'&auth_date=1','test-token'));
 assert.throws(()=>validateTelegram('hash=x','test-token'));
});
test('Uzbek plates: personal and company formats',()=>{assert.ok(validPlate('80 A 123 AA'));assert.ok(validPlate('80 123 AAA'));assert.equal(validPlate('12345678'),false);assert.equal(validPlate('<script>'),false)});
test('card encryption is authenticated and randomized',()=>{const key='ab'.repeat(32);const a=encryptCard('8600123412341234',key),b=encryptCard('8600123412341234',key);assert.notEqual(a,b);assert.equal(decryptCard(a,key),'8600123412341234');assert.throws(()=>decryptCard(a,'cc'.repeat(32)));assert.throws(()=>encryptCard('8600123412341234',''))});
