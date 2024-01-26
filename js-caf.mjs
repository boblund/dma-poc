/*

THIS SOFTWARE COMES WITHOUT ANY WARRANTY, TO THE EXTENT PERMITTED BY APPLICABLE LAW.

*/

class Channel {
	#messages = [];
	#putters = [];
	#takers = [];
	#status = 'open';

	constructor (){};

	closed() {return this.#status == 'closed';}
	close() {this.#status = 'closed';}

	put(msg) {
		return new Promise(resolve => {
			let resolveValue = true;
			if(this.closed()) {
				resolveValue = false;
			} else {
				this.#messages.unshift(msg);
			}
			this.#putters.unshift(resolve);
			if (this.#takers.length) {
				this.#putters.pop()(resolveValue);
				this.#takers.pop()(this.#messages.pop());
			}
		});
	}

	async *[Symbol.asyncIterator]() {
		if(this.closed()) return;
		while (true) {
			yield await this.take();
		}
	}

	take(asyncIterator = false) {
		return new Promise(resolve => {
			this.#takers.unshift(resolve);
			if (this.#putters.length) {
				this.#putters.pop()();
				this.#takers.pop()(this.#messages.length == 0 ? null : this.#messages.pop());
			} else if(this.closed() || asyncIterator) {
				this.#takers.pop()(null);
			}
		});
	}

	takeAll() {
		const msgs = [];
		while (this.#messages.length)
			msgs.push(this.take());
		return Promise.all(msgs);
	}
} // class Channel

function any(chArray){
	let allClosed = false,
		retArray = chArray.map((ch, idx) => {
			allClosed = allClosed || ch.closed();
			return ch.closed()
				? new Promise(()=>{}) // closed channel shouldn't resolve
				: new Promise((res) => { ch.take().then(msg => res({idx, msg})); });
		});
	return allClosed
		? new Promise(res=>{res({idx: -1, msg: null});})
		: Promise.race(retArray);
}

export {Channel, any};
