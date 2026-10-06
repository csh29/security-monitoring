<template>
  <div>
    <!-- ruleid: kisa-xss-framework-raw-html -->
    <div v-html="notice.content"></div>
    <!-- ok: kisa-xss-framework-raw-html -->
    <div>{{ notice.content }}</div>
  </div>
</template>

<script>
export default {
  mounted() {
    // ruleid: kisa-xss-innerhtml
    this.$refs.box.innerHTML = this.notice.content;
    // ok: kisa-xss-innerhtml
    this.$refs.box.textContent = this.notice.content;
  }
};
</script>
