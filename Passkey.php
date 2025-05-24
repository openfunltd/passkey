<?php
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\AuthenticatorAttestationResponse;
//common
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\AuthenticatorSelectionCriteria;
//serializer related
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Encoder\JsonEncode;
//validator related
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;

class Passkey
{
    public static function generateCreationOptions($username, $user_id, $displayname)
    {
        $rp_id = (getenv('RP_ID') !== false) ? getenv('RP_ID') : $_SERVER['SERVER_NAME'];

        //ingredients
        $RP_entity = PublicKeyCredentialRpEntity::create(getenv('APP_NAME'), $rp_id);
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
        $creation_options_string = self::serialize('creation_options', $creation_options);

        //store in session for varification later
        MiniEngine::setSession('webauthn_user_entity', serialize($user_entity));
        MiniEngine::setSession('webauthn_creation_options', $creation_options_string);

        return json_decode($creation_options_string);
    }

    public static function verifyCreation($credential_data)
    {
        $rp_id = (getenv('RP_ID') !== false) ? getenv('RP_ID') : $_SERVER['SERVER_NAME'];

        //get validator
        $validator = self::getValidator('creation');

        //get PublicKeyCredential object
        $credential = self::deserialize('credential', $credential_data);

        //check client is in attestation step
        if (!$credential->response instanceof AuthenticatorAttestationResponse) {
            return (object) ['error' => 'Invalid credential response type'];
        }

        //get credential_options from session
        $creation_options_string = MiniEngine::getSession('webauthn_creation_options');
        $creation_options = self::deserialize('creation_options', $creation_options_string);

        //vaildate
        try {
            $credential_source = $validator->check(
                $credential->response,
                $creation_options,
                $rp_id
            );
        } catch (Throwable $e) {
            return (object) ['error' => $e->getMessage()];
        }

        //serialize
        $credential_source_string = self::serialize('credential_source', $credential_source);

        return json_decode($credential_source_string);
    }

    public static function generateAuthenticationOptions()
    {
    }

    public static function verifyAuthentication()
    {
    }

    private static function serialize($type, $instance)
    {
        //get serializer
        $serializer = self::getSerializer();

        if ($type == 'creation_options') {
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

        if ($type == 'credential_source') {
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

    private static function deserialize($type, $data)
    {
        //get serializer
        $serializer = self::getSerializer();

        if ($type == 'credential') {
            return $serializer->deserialize(
                json_encode($data), //expect $data is object
                PublicKeyCredential::class,
                'json'
            );
        }

        if ($type == 'creation_options') {
            return $serializer->deserialize(
                $data, //expect $data is json_string
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
        }
    }

    private static function getValidator($type)
    {
        $csmFactory = new CeremonyStepManagerFactory();

        if ($type == 'creation') {
           $creation_CSM = $csmFactory->creationCeremony();
           return AuthenticatorAttestationResponseValidator::create($creation_CSM);
        }
    }

    private static function getSerializer()
    {
        //create manager
        $attestation_statement_support_manager = AttestationStatementSupportManager::create();
        $attestation_statement_support_manager->add(NoneAttestationStatementSupport::create());

        //create serializer
        $factory = new WebauthnSerializerFactory($attestation_statement_support_manager);
        $serializer = $factory->create();

        return $serializer;
    }
}
