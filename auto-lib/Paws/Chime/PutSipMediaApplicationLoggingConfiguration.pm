
package Paws::Chime::PutSipMediaApplicationLoggingConfiguration;
  use Moose;
  has SipMediaApplicationId => (is => 'ro', isa => 'Str', traits => ['ParamInURI'], uri_name => 'sipMediaApplicationId', required => 1);
  has SipMediaApplicationLoggingConfiguration => (is => 'ro', isa => 'Paws::Chime::SipMediaApplicationLoggingConfiguration');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'PutSipMediaApplicationLoggingConfiguration');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/sip-media-applications/{sipMediaApplicationId}/logging-configuration');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'PUT');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Chime::PutSipMediaApplicationLoggingConfigurationResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Chime::PutSipMediaApplicationLoggingConfiguration - Arguments for method PutSipMediaApplicationLoggingConfiguration on L<Paws::Chime>

=head1 DESCRIPTION

This class represents the parameters used for calling the method PutSipMediaApplicationLoggingConfiguration on the
L<Amazon Chime|Paws::Chime> service. Use the attributes of this class
as arguments to method PutSipMediaApplicationLoggingConfiguration.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to PutSipMediaApplicationLoggingConfiguration.

=head1 SYNOPSIS

    my $chime = Paws->service('Chime');
    my $PutSipMediaApplicationLoggingConfigurationResponse =
      $chime->PutSipMediaApplicationLoggingConfiguration(
      SipMediaApplicationId                   => 'MyNonEmptyString',
      SipMediaApplicationLoggingConfiguration => {
        EnableSipMediaApplicationMessageLogs => 1,    # OPTIONAL
      },    # OPTIONAL
      );

    # Results:
    my $SipMediaApplicationLoggingConfiguration =
      $PutSipMediaApplicationLoggingConfigurationResponse
      ->SipMediaApplicationLoggingConfiguration;

# Returns a L<Paws::Chime::PutSipMediaApplicationLoggingConfigurationResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/chime/PutSipMediaApplicationLoggingConfiguration>

=head1 ATTRIBUTES


=head2 B<REQUIRED> SipMediaApplicationId => Str

The SIP media application ID.



=head2 SipMediaApplicationLoggingConfiguration => L<Paws::Chime::SipMediaApplicationLoggingConfiguration>

The actual logging configuration.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method PutSipMediaApplicationLoggingConfiguration in L<Paws::Chime>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

