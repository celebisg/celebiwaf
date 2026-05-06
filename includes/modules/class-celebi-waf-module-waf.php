<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_WAF {
    public function inspect($context) {
        $result = CELEBI_WAF_Rules::evaluate($context['payload']);
        if (!$result['matched']) { return null; }

        return [
            'module' => $result['category'],
            'attack_type' => $result['category'],
            'rule_name' => $result['rule_name'],
            'risk_score' => $result['risk_score'],
            'action' => $result['action'] === 'challenge' ? 'challenge' : 'block'
        ];
    }
}
