/** Bounded FIFO shared by local policy changes and remote tool dispatch. */
export class SerialQueue {
  constructor({ capacity = 24, isClosing = () => false } = {}) {
    this.capacity = capacity;
    this.isClosing = isClosing;
    this.size = 0;
    this.tail = Promise.resolve();
  }

  run(action) {
    if (this.isClosing() || this.size >= this.capacity) {
      return Promise.reject(Object.assign(new Error('Local controller is busy or closing.'), { status: 503 }));
    }
    this.size++;
    const result = this.tail.then(action);
    this.tail = result.catch(() => {}).finally(() => { this.size--; });
    return result;
  }

  drain() { return this.tail; }
}
