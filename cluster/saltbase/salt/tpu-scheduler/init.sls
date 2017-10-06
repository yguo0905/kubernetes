/etc/kubernetes/manifests/tpu-scheduler.manifest:
  file.managed:
    - source: salt://tpu-scheduler/tpu-scheduler.manifest
    - template: jinja
    - user: root
    - group: root
    - mode: 644
    - makedirs: true
    - dir_mode: 755

/var/log/tpu-scheduler.log:
  file.managed:
    - user: root
    - group: root
    - mode: 644
