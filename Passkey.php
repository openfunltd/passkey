<?php
//generate creation options
use Webauthn\PublicKeyCredentialCreationOptions;
//common
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\AuthenticatorSelectionCriteria;
//serializer related
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Encoder\JsonEncode;

class Passkey
{
    public static function generateCreationOptions($username, $user_id, $displayname)
    {
        //ingredients
        $RP_entity = PublicKeyCredentialRpEntity::create(getenv('APP_NAME'), getenv('RELYING_PARTY_ID'));
        $user_entity = PublicKeyCredentialUserEntity::create($username, $user_id, $displayname);
        $challenge = random_bytes(32);
        $criteria = AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        );

        //generate creation options
        $creation_options = PublicKeyCredentialCreationOptions::create(
            rp: $RP_entity,
            user: $user_entity,
            challenge: $challenge,
            authenticatorSelection: $criteria,
        );

        //serialize
        $json_string = self::serialize('creation_options', $creation_options);

        //store in session for varification later
        MiniEngine::setSession('webauthn_user_entity', serialize($user_entity));
        MiniEngine::setSession('webauthn_creation_options', $json_string);

        return json_decode($json_string);
    }

    public static function verifyCreation()
    {
    }

    public static function generateAuthenticationOptions()
    {
    }

    public static function verifyAuthentication()
    {
    }

    private static function serialize($type, $instance)
    {
        //create manager
        $attestation_statement_support_manager = AttestationStatementSupportManager::create();
        $attestation_statement_support_manager->add(NoneAttestationStatementSupport::create());

        if ($type == 'creation_options') {
            //create serializer
            $factory = new WebauthnSerializerFactory($attestation_statement_support_manager);
            $serializer = $factory->create();

            $json_string = $serializer->serialize(
                $instance,
                'json',
                [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                    JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
                ]
            );

            return $json_string;
        }
    }

    private static function deserialize()
    {
    }
}
